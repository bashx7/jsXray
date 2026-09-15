"""Internal infrastructure and private IP detector for JSXRay."""

import ipaddress
import re
from typing import List, Optional
from tree_sitter import Node
from jsxray.analyzers.base import BaseAnalyzer
from jsxray.javascript.ast_utils import (
    extract_string_literal,
    get_node_line_col,
    get_node_snippet,
    get_node_text,
    walk_tree,
)
from jsxray.javascript.reconstruction import StaticReconstructor
from jsxray.models.finding import Confidence, Finding, FindingStatus, FindingType
from jsxray.models.source import JavaScriptSource


class InternalHostAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "internal_hosts"

    IPV4_REGEX = re.compile(r"\b((?:[0-9]{1,3}\.){3}[0-9]{1,3})\b")
    INTERNAL_DOMAIN_REGEX = re.compile(
        r"\b([a-zA-Z0-9_\-]+\.(?:internal|corp|local|lan|priv|home|localdomain|intra))\b",
        re.I,
    )
    LOCALHOST_REGEX = re.compile(r"\b(localhost(?::\d+)?|127\.0\.0\.1(?::\d+)?)\b", re.I)

    def analyze(self, source: JavaScriptSource, reconstructor: StaticReconstructor) -> List[Finding]:
        findings: List[Finding] = []
        if not source.ast_root:
            return findings

        code_bytes = source.effective_code.encode("utf-8", errors="replace")
        code_lines = source.effective_code.splitlines()

        for node in walk_tree(source.ast_root):
            val: Optional[str] = None
            if node.type in ("string", "string_fragment"):
                val = extract_string_literal(node, code_bytes)
            elif node.type == "template_string":
                resolved, _, _ = reconstructor.resolve_expression(node)
                val = resolved

            if not val or len(val) < 4:
                continue

            # 1. Private IPv4 addresses
            for ip_match in self.IPV4_REGEX.finditer(val):
                ip_str = ip_match.group(1)
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    if ip_obj.is_private or ip_obj.is_loopback:
                        line, col = get_node_line_col(node)
                        findings.append(
                            Finding(
                                type=FindingType.INTERNAL_HOST,
                                value=f"Private IP: {ip_str}",
                                normalized_value=ip_str,
                                confidence=Confidence.HIGH,
                                status=FindingStatus.DETECTED,
                                source_file=source.file_path,
                                source_url=source.url,
                                line=line,
                                column=col,
                                snippet=get_node_snippet(node, code_lines),
                                original_source=get_node_text(node, code_bytes).strip(),
                                reconstructed_source=ip_str,
                                discovery_method="AST analysis",
                                tags=["internal-host", "private-ip", "rfc1918"],
                                extra_data={"ip": ip_str, "is_loopback": ip_obj.is_loopback},
                            )
                        )
                except ValueError:
                    pass

            # 2. Localhost references
            for loc_match in self.LOCALHOST_REGEX.finditer(val):
                loc_str = loc_match.group(1)
                line, col = get_node_line_col(node)
                findings.append(
                    Finding(
                        type=FindingType.INTERNAL_HOST,
                        value=f"Localhost: {loc_str}",
                        normalized_value=loc_str,
                        confidence=Confidence.HIGH,
                        status=FindingStatus.DETECTED,
                        source_file=source.file_path,
                        source_url=source.url,
                        line=line,
                        column=col,
                        snippet=get_node_snippet(node, code_lines),
                        original_source=get_node_text(node, code_bytes).strip(),
                        reconstructed_source=loc_str,
                        discovery_method="AST analysis",
                        tags=["internal-host", "localhost"],
                        extra_data={"host": loc_str},
                    )
                )

            # 3. Internal top-level domains (.internal, .corp, etc.)
            for dom_match in self.INTERNAL_DOMAIN_REGEX.finditer(val):
                domain_str = dom_match.group(1)
                line, col = get_node_line_col(node)
                findings.append(
                    Finding(
                        type=FindingType.INTERNAL_HOST,
                        value=f"Internal Domain: {domain_str}",
                        normalized_value=domain_str,
                        confidence=Confidence.HIGH,
                        status=FindingStatus.DETECTED,
                        source_file=source.file_path,
                        source_url=source.url,
                        line=line,
                        column=col,
                        snippet=get_node_snippet(node, code_lines),
                        original_source=get_node_text(node, code_bytes).strip(),
                        reconstructed_source=domain_str,
                        discovery_method="AST analysis",
                        tags=["internal-host", "internal-domain"],
                        extra_data={"domain": domain_str},
                    )
                )

        return findings
