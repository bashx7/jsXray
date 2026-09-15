"""Lexical token and regex fallback analyzer for JSXRay."""

import re
from typing import List
from jsxray.models.finding import Confidence, Finding, FindingStatus, FindingType
from jsxray.models.source import JavaScriptSource


class FallbackAnalyzer:
    """Fallback lexical analyzer when AST parsing fails or for malformed JS."""

    URL_REGEX = re.compile(r"https?://[a-zA-Z0-9_\-\.:]+(?:/[^\s\"'<>`\)]*)?")
    API_PATH_REGEX = re.compile(r"['\"`](/(?:api|v[0-9]|rest|graphql|auth|admin|user|users|v1|v2)/[a-zA-Z0-9_\-/\.{}]+)['\"`]")
    WS_REGEX = re.compile(r"['\"`](wss?://[^\s\"'`]+)['\"`]")

    def analyze(self, source: JavaScriptSource) -> List[Finding]:
        findings: List[Finding] = []
        code = source.effective_code
        lines = code.splitlines()

        for line_idx, line in enumerate(lines):
            line_num = line_idx + 1

            # Match URLs
            for match in self.URL_REGEX.finditer(line):
                url = match.group(0)
                findings.append(
                    Finding(
                        type=FindingType.URL_ROUTE,
                        value=url,
                        normalized_value=url,
                        confidence=Confidence.LOW,
                        status=FindingStatus.POTENTIAL,
                        source_file=source.file_path,
                        source_url=source.url,
                        line=line_num,
                        column=match.start() + 1,
                        snippet=line.strip()[:200],
                        original_source=url,
                        discovery_method="Lexical fallback",
                        tags=["fallback", "url"],
                    )
                )

            # Match API paths
            for match in self.API_PATH_REGEX.finditer(line):
                path = match.group(1)
                findings.append(
                    Finding(
                        type=FindingType.API_ENDPOINT,
                        value=path,
                        normalized_value=path,
                        confidence=Confidence.LOW,
                        status=FindingStatus.POTENTIAL,
                        source_file=source.file_path,
                        source_url=source.url,
                        line=line_num,
                        column=match.start() + 1,
                        snippet=line.strip()[:200],
                        original_source=match.group(0),
                        discovery_method="Lexical fallback",
                        tags=["fallback", "api-route"],
                        extra_data={"method": "UNKNOWN"},
                    )
                )

            # Match WebSocket URLs
            for match in self.WS_REGEX.finditer(line):
                ws_url = match.group(1)
                findings.append(
                    Finding(
                        type=FindingType.WEBSOCKET,
                        value=ws_url,
                        normalized_value=ws_url,
                        confidence=Confidence.LOW,
                        status=FindingStatus.POTENTIAL,
                        source_file=source.file_path,
                        source_url=source.url,
                        line=line_num,
                        column=match.start() + 1,
                        snippet=line.strip()[:200],
                        original_source=match.group(0),
                        discovery_method="Lexical fallback",
                        tags=["fallback", "websocket"],
                    )
                )

        return findings
