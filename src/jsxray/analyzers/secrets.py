"""Secret and token detector for JSXRay powered by SecretDetectionEngine."""

from typing import Any, Dict, List
from jsxray.analyzers.base import BaseAnalyzer
from jsxray.javascript.reconstruction import StaticReconstructor
from jsxray.models.finding import Confidence, Finding, FindingStatus, FindingType
from jsxray.models.source import JavaScriptSource
from jsxray.secrets.engine import SecretDetectionEngine


class SecretAnalyzer(BaseAnalyzer):
    """High-precision secret analyzer leveraging 500+ vendor rules and contextual generic detectors."""

    def __init__(self) -> None:
        self.engine = SecretDetectionEngine()

    @property
    def name(self) -> str:
        return "secrets"

    def analyze(self, source: JavaScriptSource, reconstructor: StaticReconstructor) -> List[Finding]:
        findings: List[Finding] = []
        if not source.effective_code:
            return findings

        source_loc = source.file_path or source.url or "source.js"
        raw_results = self.engine.scan_content(source.effective_code, file_path=source_loc)

        for res in raw_results:
            conf_str = res.get("confidence", "Medium")
            if conf_str == "High":
                conf = Confidence.HIGH
            elif conf_str == "Low":
                conf = Confidence.LOW
            else:
                conf = Confidence.MEDIUM

            # Check for test/dummy status
            raw_val = res.get("raw_value", "")
            raw_lower = raw_val.lower()
            status = FindingStatus.DETECTED
            if any(k in raw_lower for k in ["example", "test", "dummy", "placeholder", "demo"]):
                status = FindingStatus.TEST_VALUE

            provider = res.get("provider", "Generic")
            secret_type = res.get("secret_type", "Secret")
            masked = res.get("masked_value", raw_val)

            finding = Finding(
                type=FindingType.SECRET,
                value=masked,
                normalized_value=masked,
                confidence=conf,
                status=status,
                source_file=source.file_path,
                source_url=source.url,
                line=res.get("line_number"),
                column=res.get("column"),
                snippet=res.get("code_snippet"),
                original_source=res.get("code_snippet"),
                reconstructed_source=masked,
                discovery_method=f"Secret Engine ({provider})",
                tags=["secret", provider.lower().replace(" ", "-"), secret_type.lower().replace(" ", "-")],
                extra_data={
                    "detector_id": res.get("detector_id"),
                    "provider": provider,
                    "secret_name": secret_type,
                    "category": res.get("category"),
                    "raw_secret": raw_val,
                    "masked_secret": masked,
                    "confidence_score": res.get("confidence_score"),
                    "confidence_reason": res.get("confidence_reason"),
                },
            )
            findings.append(finding)

        return findings
