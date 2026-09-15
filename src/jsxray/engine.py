"""Core scan pipeline engine for JSXRay."""

from datetime import datetime
from pathlib import Path
import time
from typing import Callable, List, Optional
import uuid

from jsxray.acquisition.downloader import Downloader
from jsxray.acquisition.encoding import decode_bytes
from jsxray.acquisition.validator import validate_javascript_content
from jsxray.analyzers import get_all_analyzers
from jsxray.analyzers.candidates import SecurityCandidateAnalyzer
from jsxray.correlation.correlate import CorrelationEngine
from jsxray.correlation.deduplicate import deduplicate_findings
from jsxray.input.local_files import discover_local_files
from jsxray.input.url_file import parse_url_file
from jsxray.javascript.fallback import FallbackAnalyzer
from jsxray.javascript.parser import JSParser
from jsxray.javascript.reconstruction import StaticReconstructor
from jsxray.models.finding import Finding
from jsxray.models.scan import ScanMetadata, ScanResult
from jsxray.models.source import JavaScriptSource
from jsxray.reporting.html import HtmlReporter
from jsxray.utils.logging import Logger


def infer_domain_from_urls(urls: List[str]) -> Optional[str]:
    from collections import Counter
    from urllib.parse import urlparse
    domains = []
    for u in urls:
        try:
            cleaned = u.strip()
            if not cleaned or cleaned.startswith("#"):
                continue
            if "://" not in cleaned:
                cleaned = f"https://{cleaned}"
            parsed = urlparse(cleaned)
            host = (parsed.netloc or parsed.path).split(":")[0].strip().lower()
            if "/" in host:
                host = host.split("/")[0]
            if host and "." in host and not host.startswith("."):
                parts = host.split(".")
                if len(parts) >= 2:
                    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "gov", "edu") and len(parts[-1]) == 2:
                        root = ".".join(parts[-3:])
                    else:
                        root = ".".join(parts[-2:])
                    domains.append(root)
                else:
                    domains.append(host)
        except Exception:
            continue
    if not domains:
        return None
    return Counter(domains).most_common(1)[0][0]


class JSXRayEngine:
    """Orchestrates source acquisition, AST parsing, intelligence analyzers, and reporting."""

    def __init__(
        self,
        url_file: Optional[str] = None,
        js_path: Optional[str] = None,
        output_file: str = "jsxray-results.html",
        target_domain: Optional[str] = None,
        downloader_workers: int = 10,
        request_timeout: int = 10,
        verify_ssl: bool = True,
    ) -> None:
        self.url_file = url_file
        self.js_path = js_path
        self.output_file = output_file
        self.target_domain = target_domain.lower().strip() if target_domain else None
        self.inferred_domain = False
        self.downloader = Downloader(
            timeout=request_timeout,
            verify_ssl=verify_ssl,
            max_workers=downloader_workers,
        )
        self.parser = JSParser()
        self.fallback = FallbackAnalyzer()
        self.candidate_analyzer = SecurityCandidateAnalyzer()
        self.analyzers = get_all_analyzers(target_domain=self.target_domain)

    def run(self) -> ScanResult:
        start_time = time.time()
        start_iso = datetime.now().isoformat()
        scan_id = str(uuid.uuid4())[:8]

        target_input = self.url_file or self.js_path or "unknown"
        input_mode = "URL List" if self.url_file else "Local JS File(s)"

        # 1. Acquire Sources
        sources: List[JavaScriptSource] = []
        if self.url_file:
            urls = parse_url_file(self.url_file)
            Logger.info(f"Loaded {len(urls)} JavaScript URLs from {self.url_file}")
            
            # Infer target domain if not explicitly provided
            if not self.target_domain and urls:
                inferred = infer_domain_from_urls(urls)
                if inferred:
                    self.target_domain = inferred
                    self.inferred_domain = True
                    self.analyzers = get_all_analyzers(target_domain=self.target_domain)
                    Logger.info(f"Inferred target domain from URLs: {self.target_domain}")

            if urls:
                sources = self.downloader.download_all(urls)
                valid_count = sum(1 for s in sources if s.is_valid_js)
                Logger.info(f"Downloaded {len(sources)} sources ({valid_count} valid JavaScript)")
                if valid_count < len(sources):
                    for s in sources:
                        if not s.is_valid_js:
                            reasons = s.errors + s.warnings
                            msg = ", ".join(reasons) if reasons else "Invalid JavaScript or blocked by server"
                            Logger.warning(f"Failed to fetch/validate: {s.identifier} ({msg})")
        elif self.js_path:
            if self.target_domain:
                Logger.info(f"Scoped target domain: {self.target_domain}")
            else:
                Logger.info("No target domain specified (Use -d domain.com to scope in-domain subdomains)")

            file_paths = discover_local_files(self.js_path)
            Logger.info(f"Discovered {len(file_paths)} JavaScript files in {self.js_path}")
            for fp in file_paths:
                try:
                    with open(fp, "rb") as f:
                        raw_bytes = f.read()
                    code, encoding = decode_bytes(raw_bytes)
                    is_valid, val_err = validate_javascript_content(code, filename=str(fp))
                    src = JavaScriptSource(
                        identifier=str(fp),
                        original_code=code,
                        file_path=str(fp),
                        encoding=encoding,
                        size_bytes=len(raw_bytes),
                        is_valid_js=is_valid,
                    )
                    if not is_valid and val_err:
                        src.warnings.append(val_err)
                    sources.append(src)
                except Exception as e:
                    Logger.warning(f"Failed to read file {fp}: {e}")
                    scan_result.errors.append({"source": str(fp), "error": str(e)})

        metadata = ScanMetadata(
            scan_id=scan_id,
            target_input=target_input,
            input_mode=input_mode,
            target_domain=self.target_domain,
            inferred_domain=self.inferred_domain,
            start_time=start_iso,
        )
        scan_result = ScanResult(metadata=metadata)
        scan_result.sources = sources

        # 2. Process Sources & Analyze
        all_findings: List[Finding] = []

        for source in sources:
            if not source.is_valid_js or not source.original_code:
                continue

            # Parse AST directly using native Tree-sitter for maximum performance
            tree, parse_err = self.parser.parse(source.original_code)
            if tree and tree.root_node:
                source.ast_root = tree.root_node
                reconstructor = StaticReconstructor(tree.root_node, source.original_code)

                # Run all primary static analyzers
                for analyzer in self.analyzers:
                    try:
                        found = analyzer.analyze(source, reconstructor)
                        all_findings.extend(found)
                    except Exception as e:
                        source.warnings.append(f"Analyzer '{analyzer.name}' warning: {e}")
            else:
                # AST parsing failed: use fallback lexical analyzer
                source.parse_error = parse_err
                fallback_found = self.fallback.analyze(source)
                all_findings.extend(fallback_found)

        # 3. Synthesize Security Testing Candidates from raw findings
        candidate_findings = self.candidate_analyzer.generate_candidates_from_findings(all_findings)
        all_findings.extend(candidate_findings)

        # 4. Deduplicate & Aggregate Occurrences
        deduped = deduplicate_findings(all_findings)
        scan_result.findings = deduped

        # 5. Correlate Relationships (Host -> Endpoints -> Auth)
        relationships = CorrelationEngine.correlate(deduped)

        # 6. Calculate Scan Duration & Stats
        end_time = time.time()
        metadata.duration_seconds = end_time - start_time
        metadata.end_time = datetime.now().isoformat()
        scan_result.calculate_statistics()

        # 7. Render & Write Self-Contained HTML Report
        reporter = HtmlReporter(scan_result, relationships=relationships)
        html_content = reporter.generate()
        out_path = Path(self.output_file).expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return scan_result
