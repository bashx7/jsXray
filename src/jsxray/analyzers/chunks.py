"""Dynamic import and JavaScript chunk detector for JSXRay."""

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


class ChunkAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "chunks"

    def analyze(self, source: JavaScriptSource, reconstructor: StaticReconstructor) -> List[Finding]:
        findings: List[Finding] = []
        if not source.ast_root:
            return findings

        code_bytes = source.effective_code.encode("utf-8", errors="replace")
        code_lines = source.effective_code.splitlines()

        for node in walk_tree(source.ast_root):
            # 1. import(...) call expression
            if node.type in ("call_expression", "import_expression"):
                func_node = node.child_by_field_name("function") or node.child_by_field_name("source")
                args_node = node.child_by_field_name("arguments")

                is_dynamic_import = False
                arg_target: Optional[Node] = None

                if node.type == "import_expression":
                    is_dynamic_import = True
                    arg_target = node.child_by_field_name("source")
                elif func_node:
                    func_text = get_node_text(func_node, code_bytes).strip()
                    if func_text == "import" and args_node:
                        is_dynamic_import = True
                        args = [c for c in args_node.children if c.type not in ("(", ")", ",")]
                        if args:
                            arg_target = args[0]

                if is_dynamic_import and arg_target:
                    resolved, trans, conf = reconstructor.resolve_expression(arg_target)
                    display_chunk = resolved or get_node_text(arg_target, code_bytes).strip().strip("\"'`")
                    line, col = get_node_line_col(node)
                    findings.append(
                        Finding(
                            type=FindingType.DYNAMIC_IMPORT,
                            value=f"Dynamic Import: {display_chunk}",
                            normalized_value=display_chunk,
                            confidence=conf,
                            status=FindingStatus.DETECTED,
                            source_file=source.file_path,
                            source_url=source.url,
                            line=line,
                            column=col,
                            snippet=get_node_snippet(node, code_lines),
                            original_source=get_node_text(node, code_bytes).strip(),
                            reconstructed_source=display_chunk,
                            discovery_method="AST analysis",
                            tags=["dynamic-import", "js-chunk"],
                            extra_data={"chunk_path": display_chunk, "transformations": trans},
                        )
                    )

        return findings
