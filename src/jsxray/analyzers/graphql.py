"""GraphQL endpoint, query, mutation, and variable detector for JSXRay."""

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


class GraphQLAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "graphql"

    GQL_ENDPOINT_REGEX = re.compile(r"^https?://[^\s\"'`]+/graphql$|/graphql$|/api/graphql$|/v[0-9]+/graphql$", re.I)
    GQL_OPERATION_REGEX = re.compile(r"\b(query|mutation|subscription)\s+([a-zA-Z0-9_]+)(?:\s*\(([^\)]*)\))?", re.I)
    GQL_VAR_REGEX = re.compile(r"\$([a-zA-Z0-9_]+)")

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
                val = resolved or get_node_text(node, code_bytes)

            if not val:
                continue

            # 1. GraphQL Endpoints
            if self.GQL_ENDPOINT_REGEX.search(val.strip()):
                line, col = get_node_line_col(node)
                findings.append(
                    Finding(
                        type=FindingType.GRAPHQL,
                        value=f"GraphQL Endpoint: {val.strip()}",
                        normalized_value=val.strip(),
                        confidence=Confidence.HIGH,
                        status=FindingStatus.DETECTED,
                        source_file=source.file_path,
                        source_url=source.url,
                        line=line,
                        column=col,
                        snippet=get_node_snippet(node, code_lines),
                        original_source=get_node_text(node, code_bytes).strip(),
                        reconstructed_source=val.strip(),
                        discovery_method="AST analysis",
                        tags=["graphql", "graphql-endpoint"],
                        extra_data={"item_type": "endpoint", "endpoint": val.strip()},
                    )
                )

            # 2. GraphQL Operations (Queries, Mutations, Subscriptions)
            for op_match in self.GQL_OPERATION_REGEX.finditer(val):
                op_type = op_match.group(1).capitalize()
                op_name = op_match.group(2)
                var_str = op_match.group(3) or ""
                variables = self.GQL_VAR_REGEX.findall(var_str)

                line, col = get_node_line_col(node)
                findings.append(
                    Finding(
                        type=FindingType.GRAPHQL,
                        value=f"GraphQL {op_type}: {op_name}",
                        normalized_value=f"{op_type} {op_name}",
                        confidence=Confidence.HIGH,
                        status=FindingStatus.DETECTED,
                        source_file=source.file_path,
                        source_url=source.url,
                        line=line,
                        column=col,
                        snippet=get_node_snippet(node, code_lines),
                        original_source=get_node_text(node, code_bytes).strip(),
                        reconstructed_source=op_match.group(0),
                        discovery_method="AST analysis",
                        tags=["graphql", f"graphql-{op_type.lower()}"],
                        extra_data={
                            "item_type": "operation",
                            "operation_type": op_type,
                            "operation_name": op_name,
                            "variables": variables,
                        },
                    )
                )

        return findings
