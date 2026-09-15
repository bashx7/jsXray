"""Source map reference and mapping analyzer for JSXRay."""

import base64
import json
import re
from typing import List, Optional
from jsxray.analyzers.base import BaseAnalyzer
from jsxray.javascript.reconstruction import StaticReconstructor
from jsxray.models.finding import Confidence, Finding, FindingStatus, FindingType
from jsxray.models.source import JavaScriptSource


class SourceMapAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "source_maps"

    SOURCEMAP_REGEX = re.compile(r"//[#@]\s*sourceMappingURL=([^\s]+)", re.I)

    def analyze(self, source: JavaScriptSource, reconstructor: StaticReconstructor) -> List[Finding]:
        findings: List[Finding] = []
        code = source.original_code or source.effective_code
        lines = code.splitlines()

        for line_idx, line in enumerate(lines):
            match = self.SOURCEMAP_REGEX.search(line)
            if match:
                map_url = match.group(1).strip()
                is_data_uri = map_url.startswith("data:application/json;base64,")
                sources_list = []

                if is_data_uri:
                    try:
                        b64_payload = map_url.split(",", 1)[1]
                        json_data = json.loads(base64.b64decode(b64_payload).decode("utf-8", errors="replace"))
                        sources_list = json_data.get("sources", [])
                    except Exception:
                        pass

                display_val = f"Source Map: {map_url[:80]}..." if len(map_url) > 80 else f"Source Map: {map_url}"

                findings.append(
                    Finding(
                        type=FindingType.SOURCE_MAP,
                        value=display_val,
                        normalized_value=map_url if not is_data_uri else "inline-sourcemap",
                        confidence=Confidence.HIGH,
                        status=FindingStatus.DETECTED,
                        source_file=source.file_path,
                        source_url=source.url,
                        line=line_idx + 1,
                        column=match.start() + 1,
                        snippet=line.strip()[:200],
                        original_source=match.group(0),
                        reconstructed_source=map_url,
                        discovery_method="AST analysis",
                        tags=["source-map", "inline" if is_data_uri else "external-map"],
                        extra_data={
                            "map_url": map_url,
                            "is_inline": is_data_uri,
                            "original_sources": sources_list[:20],
                        },
                    )
                )

        return findings
