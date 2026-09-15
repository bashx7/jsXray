"""Security testing candidate classifier for JSXRay.

Synthesizes high-value penetration testing candidates from validated application endpoints
while strictly excluding browser standard namespaces, static assets, and framework boilerplate.
"""

import re
from typing import List, Set
from urllib.parse import urlparse
from jsxray.analyzers.base import BaseAnalyzer
from jsxray.javascript.reconstruction import StaticReconstructor
from jsxray.models.finding import Confidence, Finding, FindingStatus, FindingType
from jsxray.models.source import JavaScriptSource


class SecurityCandidateAnalyzer(BaseAnalyzer):
    """Categorizes high-value security testing candidates from confirmed endpoints and parameters."""

    @property
    def name(self) -> str:
        return "candidates"

    # Specific patterns indicating object/resource identifiers in application endpoints (IDOR / BOLA candidates)
    IDOR_PARAM_REGEX = re.compile(
        r"/\{([a-zA-Z0-9_]*(?:id|uuid|account|user|order|item|doc|invoice|patient|profile|org|team|project)[a-zA-Z0-9_]*)\}|/:(id|userId|accountId|orderId|docId|profileId|itemId|invoiceId)\b",
        re.I,
    )
    ADMIN_ROUTE_REGEX = re.compile(
        r"^/(?:api/)?(?:v[0-9]+/)?(admin|manage|dashboard|super|root|internal|control|operator)(?:/|$)",
        re.I,
    )
    FILE_OP_REGEX = re.compile(
        r"^/(?:api/)?(?:v[0-9]+/)?(upload|download|export|import|attachment|avatar|documents/upload)(?:/|$)",
        re.I,
    )
    REDIRECT_PARAM_REGEX = re.compile(
        r"[\?&](?:redirect|return|return_to|goto|next|callback|url|destination|continue)=([^\s&]+)",
        re.I,
    )

    STANDARD_DOMAINS = ("www.w3.org", "w3.org", "schema.org", "xmlns.com", "svelte.dev", "reactjs.org")

    def analyze(self, source: JavaScriptSource, reconstructor: StaticReconstructor) -> List[Finding]:
        return []

    def is_standard_or_static(self, val: str) -> bool:
        """Determines if string is a browser namespace, static file, or framework link."""
        if not val:
            return True
        v_clean = val.lower().split("?")[0].strip()
        if any(d in v_clean for d in self.STANDARD_DOMAINS):
            return True
        if v_clean.endswith((".js", ".css", ".map", ".wasm", ".svg", ".png", ".jpg", ".jpeg", ".woff", ".woff2", ".ttf")):
            return True
        if any(p in v_clean for p in ("/cdn/", "/assets/", "/static/", "/chunks/", "/node_modules/", "/_next/static/")):
            return True
        return False

    def generate_candidates_from_findings(self, raw_findings: List[Finding]) -> List[Finding]:
        """Synthesizes high-value security testing candidates from across all collected findings."""
        candidates: List[Finding] = []
        seen_targets: Set[str] = set()

        for f in raw_findings:
            norm = f.normalized_value or f.value
            if self.is_standard_or_static(norm):
                continue

            # 1. Authorization / IDOR Testing Candidate (Must have genuine resource identifier in route)
            if f.type in (FindingType.API_ENDPOINT, FindingType.URL_ROUTE):
                if self.IDOR_PARAM_REGEX.search(norm):
                    key = f"idor:{norm}"
                    if key not in seen_targets:
                        seen_targets.add(key)
                        candidates.append(
                            Finding(
                                type=FindingType.SECURITY_CANDIDATE,
                                value=f"Testing Candidate (Authorization / IDOR): {norm}",
                                normalized_value=norm,
                                confidence=Confidence.MEDIUM,
                                status=FindingStatus.POTENTIAL,
                                source_file=f.source_file,
                                source_url=f.source_url,
                                line=f.line,
                                column=f.column,
                                snippet=f.snippet,
                                original_source=f.original_source,
                                reconstructed_source=norm,
                                discovery_method="Correlation engine",
                                tags=["testing-candidate", "authorization-testing", "idor-candidate"],
                                extra_data={
                                    "target": norm,
                                    "category": "Authorization / IDOR Candidate",
                                    "rationale": "Endpoint references dynamic resource/object identifier for permission testing.",
                                },
                            )
                        )

            # 2. Privileged Access Surface Candidate (/admin, /manage)
            if f.type in (FindingType.API_ENDPOINT, FindingType.URL_ROUTE):
                if self.ADMIN_ROUTE_REGEX.search(norm):
                    key = f"admin:{norm}"
                    if key not in seen_targets:
                        seen_targets.add(key)
                        candidates.append(
                            Finding(
                                type=FindingType.SECURITY_CANDIDATE,
                                value=f"Testing Candidate (Privileged Surface): {norm}",
                                normalized_value=norm,
                                confidence=Confidence.HIGH if f.type == FindingType.API_ENDPOINT else Confidence.MEDIUM,
                                status=FindingStatus.POTENTIAL,
                                source_file=f.source_file,
                                source_url=f.source_url,
                                line=f.line,
                                column=f.column,
                                snippet=f.snippet,
                                original_source=f.original_source,
                                reconstructed_source=norm,
                                discovery_method="Correlation engine",
                                tags=["testing-candidate", "admin-surface", "privilege-testing"],
                                extra_data={
                                    "target": norm,
                                    "category": "Privileged Surface Candidate",
                                    "rationale": "Endpoint references administrative or backend management route.",
                                },
                            )
                        )

            # 3. File Handling Candidate (upload, download, attachment)
            if f.type in (FindingType.API_ENDPOINT, FindingType.URL_ROUTE):
                if self.FILE_OP_REGEX.search(norm):
                    key = f"fileop:{norm}"
                    if key not in seen_targets:
                        seen_targets.add(key)
                        candidates.append(
                            Finding(
                                type=FindingType.SECURITY_CANDIDATE,
                                value=f"Testing Candidate (File Handling): {norm}",
                                normalized_value=norm,
                                confidence=Confidence.HIGH if f.type == FindingType.API_ENDPOINT else Confidence.MEDIUM,
                                status=FindingStatus.POTENTIAL,
                                source_file=f.source_file,
                                source_url=f.source_url,
                                line=f.line,
                                column=f.column,
                                snippet=f.snippet,
                                original_source=f.original_source,
                                reconstructed_source=norm,
                                discovery_method="Correlation engine",
                                tags=["testing-candidate", "file-operation", "upload-download-target"],
                                extra_data={
                                    "target": norm,
                                    "category": "File Handling Candidate",
                                    "rationale": "Endpoint accepts file uploads or triggers file retrieval.",
                                },
                            )
                        )

            # 4. Open Redirect Candidate (from dynamic redirection parameters in endpoints)
            if f.type in (FindingType.API_ENDPOINT, FindingType.URL_ROUTE):
                if self.REDIRECT_PARAM_REGEX.search(norm):
                    key = f"redirect:{norm}"
                    if key not in seen_targets:
                        seen_targets.add(key)
                        candidates.append(
                            Finding(
                                type=FindingType.SECURITY_CANDIDATE,
                                value=f"Testing Candidate (Open Redirect): {norm}",
                                normalized_value=norm,
                                confidence=Confidence.MEDIUM,
                                status=FindingStatus.POTENTIAL,
                                source_file=f.source_file,
                                source_url=f.source_url,
                                line=f.line,
                                column=f.column,
                                snippet=f.snippet,
                                original_source=f.original_source,
                                reconstructed_source=norm,
                                discovery_method="Correlation engine",
                                tags=["testing-candidate", "open-redirect-candidate"],
                                extra_data={
                                    "target": norm,
                                    "category": "Open Redirect Candidate",
                                    "rationale": "Endpoint accepts dynamic URL redirection/destination parameter.",
                                },
                            )
                        )

            # 5. Internal Infrastructure / SSRF Candidate
            if f.type == FindingType.INTERNAL_HOST:
                key = f"ssrf:{norm}"
                if key not in seen_targets:
                    seen_targets.add(key)
                    candidates.append(
                        Finding(
                            type=FindingType.SECURITY_CANDIDATE,
                            value=f"Testing Candidate (Internal Pivot / SSRF): {norm}",
                            normalized_value=norm,
                            confidence=Confidence.HIGH,
                            status=FindingStatus.POTENTIAL,
                            source_file=f.source_file,
                            source_url=f.source_url,
                            line=f.line,
                            column=f.column,
                            snippet=f.snippet,
                            original_source=f.original_source,
                            reconstructed_source=norm,
                            discovery_method="Correlation engine",
                            tags=["testing-candidate", "internal-pivot", "ssrf-target"],
                            extra_data={
                                "target": norm,
                                "category": "Internal Infrastructure Candidate",
                                "rationale": "Internal RFC 1918 address or internal private domain referenced in source.",
                            },
                        )
                    )

        return candidates
