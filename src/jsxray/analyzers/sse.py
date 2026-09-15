"""Server-Sent Events (EventSource) analyzer for JSXRay."""

from typing import List, Optional
from tree_sitter import Node
from jsxray.analyzers.base import BaseAnalyzer
from jsxray.javascript.ast_utils import (
    get_node_line_col,
    get_node_snippet,
    get_node_text,
    walk_tree,
)
from jsxray.javascript.reconstruction import StaticReconstructor
from jsxray.models.finding import Confidence, Finding, FindingStatus, FindingType
from jsxray.models.source import JavaScriptSource


class SSEAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "sse"

    def analyze(self, source: JavaScriptSource, reconstructor: StaticReconstructor) -> List[Finding]:
        findings: List[Finding] = []
        if not source.ast_root:
            return findings

        code_bytes = source.effective_code.encode("utf-8", errors="replace")
        code_lines = source.effective_code.splitlines()

        for node in walk_tree(source.ast_root):
            # new EventSource(url)
            if node.type == "new_expression":
                constructor_node = node.child_by_field_name("constructor")
                args_node = node.child_by_field_name("arguments")
                if constructor_node and args_node:
                    c_name = get_node_text(constructor_node, code_bytes).strip()
                    if c_name == "EventSource":
                        args = [c for c in args_node.children if c.type not in ("(", ")", ",")]
                        if args:
                            resolved_url, trans, conf = reconstructor.resolve_expression(args[0])
                            if resolved_url:
                                line, col = get_node_line_col(node)
                                findings.append(
                                    Finding(
                                        type=FindingType.SSE,
                                        value=f"SSE: {resolved_url}",
                                        normalized_value=resolved_url,
                                        confidence=conf,
                                        status=FindingStatus.DETECTED,
                                        source_file=source.file_path,
                                        source_url=source.url,
                                        line=line,
                                        column=col,
                                        snippet=get_node_snippet(node, code_lines),
                                        original_source=get_node_text(node, code_bytes).strip(),
                                        reconstructed_source=resolved_url,
                                        discovery_method="AST analysis",
                                        tags=["sse", "eventsource", "streaming"],
                                        extra_data={"url": resolved_url, "transformations": trans},
                                    )
                                )

        return findings
