"""Request parameter analyzer for JSXRay.

Extracts real HTTP query, path, and body parameters from requests and endpoints
while filtering out CSS, Tailwind, HTML, and arbitrary variable noise.
"""

import re
from typing import List, Optional, Set
from urllib.parse import parse_qs, urlparse
from tree_sitter import Node
from jsxray.analyzers.base import BaseAnalyzer
from jsxray.javascript.ast_utils import (
    extract_string_literal,
    get_node_line_col,
    get_node_snippet,
    get_node_text,
    get_object_properties,
    walk_tree,
)
from jsxray.javascript.reconstruction import StaticReconstructor
from jsxray.models.finding import Confidence, Finding, FindingStatus, FindingType
from jsxray.models.source import JavaScriptSource


class ParameterAnalyzer(BaseAnalyzer):
    """Accurately extracts genuine HTTP parameters from requests, paths, and query builders."""

    @property
    def name(self) -> str:
        return "parameters"

    # Path parameter regex requiring leading slash: /\{param\} or /:param
    PATH_PARAM_REGEX = re.compile(r"/\{([a-zA-Z0-9_]{1,64})\}|/:([a-zA-Z0-9_]{1,64})(?:/|$|\?|\#)")

    # Common CSS / Tailwind / HTML attribute false positives
    CSS_AND_UI_KEYWORDS = {
        "bg", "text", "border", "opacity", "hover", "invert", "underline",
        "flex", "grid", "rounded", "shadow", "transition", "transform",
        "duration", "ease", "gap", "justify", "items", "self", "content",
        "w", "h", "p", "m", "px", "py", "mx", "my", "sm", "md", "lg", "xl",
        "dark", "focus", "active", "disabled", "first", "last", "odd", "even",
        "class", "classname", "style", "id", "key", "ref", "children",
    }

    PARAM_NAME_REGEX = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_\-\.]{0,63}$")

    @classmethod
    def is_valid_parameter_name(cls, name: str) -> bool:
        """Validates parameter name and filters out CSS, Tailwind, or punctuation noise."""
        if not name or len(name) < 1 or len(name) > 64:
            return False
        n_lower = name.lower()
        if n_lower in cls.CSS_AND_UI_KEYWORDS:
            return False
        if not cls.PARAM_NAME_REGEX.match(name):
            return False
        # Discard strings with colons (CSS pseudo-classes) or spaces
        if ":" in name or " " in name or "/" in name or "\\" in name:
            return False
        return True

    def analyze(self, source: JavaScriptSource, reconstructor: StaticReconstructor) -> List[Finding]:
        findings: List[Finding] = []
        if not source.ast_root:
            return findings

        code_bytes = source.effective_code.encode("utf-8", errors="replace")
        code_lines = source.effective_code.splitlines()
        seen_params: Set[str] = set()

        for node in walk_tree(source.ast_root):
            # 1. Path parameters in URL templates: /api/users/{userId} or /orders/:orderId
            if node.type in ("string", "template_string", "binary_expression"):
                resolved, _, _ = reconstructor.resolve_expression(node)
                if resolved and ("/" in resolved or "?" in resolved):
                    # Path parameters
                    for match in self.PATH_PARAM_REGEX.finditer(resolved):
                        p_name = match.group(1) or match.group(2)
                        if self.is_valid_parameter_name(p_name):
                            p_key = f"path:{p_name}:{resolved[:80]}"
                            if p_key not in seen_params:
                                seen_params.add(p_key)
                                line, col = get_node_line_col(node)
                                snippet = get_node_snippet(node, code_lines, code_bytes=code_bytes)
                                findings.append(
                                    Finding(
                                        type=FindingType.PARAMETER,
                                        value=p_name,
                                        normalized_value=p_name,
                                        confidence=Confidence.HIGH,
                                        status=FindingStatus.DETECTED,
                                        source_file=source.file_path,
                                        source_url=source.url,
                                        line=line,
                                        column=col,
                                        snippet=snippet,
                                        original_source=get_node_text(node, code_bytes).strip(),
                                        reconstructed_source=p_name,
                                        discovery_method="AST analysis",
                                        tags=["parameter", "path-parameter"],
                                        extra_data={
                                            "name": p_name,
                                            "param_type": "path",
                                            "endpoint": resolved,
                                            "evidence": snippet,
                                            "caller": "path-template",
                                        },
                                    )
                                )

                    # Query parameters from literal URLs: /api/users?id=123&status=active
                    if "?" in resolved:
                        try:
                            parsed = urlparse(resolved)
                            query_params = parse_qs(parsed.query)
                            for q_param in query_params.keys():
                                if self.is_valid_parameter_name(q_param):
                                    p_key = f"query:{q_param}:{resolved[:80]}"
                                    if p_key not in seen_params:
                                        seen_params.add(p_key)
                                        line, col = get_node_line_col(node)
                                        snippet = get_node_snippet(node, code_lines, code_bytes=code_bytes)
                                        findings.append(
                                            Finding(
                                                type=FindingType.PARAMETER,
                                                value=q_param,
                                                normalized_value=q_param,
                                                confidence=Confidence.HIGH,
                                                status=FindingStatus.DETECTED,
                                                source_file=source.file_path,
                                                source_url=source.url,
                                                line=line,
                                                column=col,
                                                snippet=snippet,
                                                original_source=get_node_text(node, code_bytes).strip(),
                                                reconstructed_source=q_param,
                                                discovery_method="AST analysis",
                                                tags=["parameter", "query-parameter"],
                                                extra_data={
                                                    "name": q_param,
                                                    "param_type": "query",
                                                    "endpoint": resolved,
                                                    "evidence": snippet,
                                                    "caller": "query-string",
                                                },
                                            )
                                        )
                        except Exception:
                            pass

            # 2. HTTP Client Requests (fetch, axios) and URLSearchParams
            elif node.type == "call_expression":
                func_node = node.child_by_field_name("function")
                args_node = node.child_by_field_name("arguments")
                if not func_node or not args_node:
                    continue

                func_name = get_node_text(func_node, code_bytes).strip()
                args = [c for c in args_node.children if c.type not in ("(", ")", ",")]
                if not args:
                    continue

                # 2A. fetch(url, { body: JSON.stringify({ ... }) })
                if func_name in ("fetch", "window.fetch") and len(args) > 1 and args[1].type == "object":
                    endpoint_val, _, _ = reconstructor.resolve_expression(args[0])
                    props = get_object_properties(args[1], code_bytes)
                    if "body" in props and props["body"].type == "call_expression":
                        body_args = props["body"].child_by_field_name("arguments")
                        if body_args:
                            b_args = [c for c in body_args.children if c.type not in ("(", ")", ",")]
                            if b_args and b_args[0].type == "object":
                                body_props = get_object_properties(b_args[0], code_bytes)
                                for p_name, p_node in body_props.items():
                                    if self.is_valid_parameter_name(p_name):
                                        p_key = f"body:{p_name}:{endpoint_val or 'fetch'}"
                                        if p_key not in seen_params:
                                            seen_params.add(p_key)
                                            line, col = get_node_line_col(p_node)
                                            snippet = get_node_snippet(node, code_lines, code_bytes=code_bytes)
                                            findings.append(
                                                Finding(
                                                    type=FindingType.PARAMETER,
                                                    value=p_name,
                                                    normalized_value=p_name,
                                                    confidence=Confidence.HIGH,
                                                    status=FindingStatus.DETECTED,
                                                    source_file=source.file_path,
                                                    source_url=source.url,
                                                    line=line,
                                                    column=col,
                                                    snippet=snippet,
                                                    original_source=get_node_text(p_node, code_bytes).strip(),
                                                    reconstructed_source=p_name,
                                                    discovery_method="AST analysis",
                                                    tags=["parameter", "body-parameter"],
                                                    extra_data={
                                                        "name": p_name,
                                                        "param_type": "body",
                                                        "endpoint": endpoint_val or "fetch",
                                                        "evidence": snippet,
                                                        "caller": "fetch",
                                                    },
                                                )
                                            )

                # 2B. axios.get(url, { params: { accountId, status } }) or axios.post(url, { ... })
                elif (func_name.startswith("axios.") or func_name == "axios" or func_name.startswith("http.") or func_name.startswith("apiClient.")) and len(args) > 1:
                    endpoint_val, _, _ = reconstructor.resolve_expression(args[0])
                    options_node = args[1] if args[1].type == "object" else (args[2] if len(args) > 2 and args[2].type == "object" else None)

                    # Check params: { ... } in options
                    if options_node:
                        opt_props = get_object_properties(options_node, code_bytes)
                        if "params" in opt_props and opt_props["params"].type == "object":
                            param_props = get_object_properties(opt_props["params"], code_bytes)
                            for p_name, p_node in param_props.items():
                                if self.is_valid_parameter_name(p_name):
                                    p_key = f"query:{p_name}:{endpoint_val or func_name}"
                                    if p_key not in seen_params:
                                        seen_params.add(p_key)
                                        line, col = get_node_line_col(p_node)
                                        snippet = get_node_snippet(node, code_lines, code_bytes=code_bytes)
                                        findings.append(
                                            Finding(
                                                type=FindingType.PARAMETER,
                                                value=p_name,
                                                normalized_value=p_name,
                                                confidence=Confidence.HIGH,
                                                status=FindingStatus.DETECTED,
                                                source_file=source.file_path,
                                                source_url=source.url,
                                                line=line,
                                                column=col,
                                                snippet=snippet,
                                                original_source=get_node_text(p_node, code_bytes).strip(),
                                                reconstructed_source=p_name,
                                                discovery_method="AST analysis",
                                                tags=["parameter", "query-parameter"],
                                                extra_data={
                                                    "name": p_name,
                                                    "param_type": "query",
                                                    "endpoint": endpoint_val or func_name,
                                                    "evidence": snippet,
                                                    "caller": func_name,
                                                },
                                            )
                                        )

                    # Check direct POST data: axios.post(url, { accountId, status })
                    method_sub = func_name.split(".")[-1].lower() if "." in func_name else ""
                    if method_sub in ("post", "put", "patch") and args[1].type == "object":
                        body_props = get_object_properties(args[1], code_bytes)
                        for p_name, p_node in body_props.items():
                            if self.is_valid_parameter_name(p_name):
                                p_key = f"body:{p_name}:{endpoint_val or func_name}"
                                if p_key not in seen_params:
                                    seen_params.add(p_key)
                                    line, col = get_node_line_col(p_node)
                                    snippet = get_node_snippet(node, code_lines, code_bytes=code_bytes)
                                    findings.append(
                                        Finding(
                                            type=FindingType.PARAMETER,
                                            value=p_name,
                                            normalized_value=p_name,
                                            confidence=Confidence.HIGH,
                                            status=FindingStatus.DETECTED,
                                            source_file=source.file_path,
                                            source_url=source.url,
                                            line=line,
                                            column=col,
                                            snippet=snippet,
                                            original_source=get_node_text(p_node, code_bytes).strip(),
                                            reconstructed_source=p_name,
                                            discovery_method="AST analysis",
                                            tags=["parameter", "body-parameter"],
                                            extra_data={
                                                "name": p_name,
                                                "param_type": "body",
                                                "endpoint": endpoint_val or func_name,
                                                "evidence": snippet,
                                                "caller": func_name,
                                            },
                                        )
                                    )

                # 2C. Explicit URLSearchParams instances:
                # searchParams.append("token", ...), searchParams.set("id", ...), params.get("page")
                elif any(sp in func_name.lower() for sp in ("searchparam", "queryparam", "urlparam", "formdata", "params.")):
                    if func_name.endswith((".append", ".set", ".get", ".has", ".delete")) and len(args) >= 1:
                        k_val, _, _ = reconstructor.resolve_expression(args[0])
                        if k_val and self.is_valid_parameter_name(k_val):
                            p_key = f"query:{k_val}:{func_name}"
                            if p_key not in seen_params:
                                seen_params.add(p_key)
                                line, col = get_node_line_col(args[0])
                                snippet = get_node_snippet(node, code_lines, code_bytes=code_bytes)
                                findings.append(
                                    Finding(
                                        type=FindingType.PARAMETER,
                                        value=k_val,
                                        normalized_value=k_val,
                                        confidence=Confidence.HIGH,
                                        status=FindingStatus.DETECTED,
                                        source_file=source.file_path,
                                        source_url=source.url,
                                        line=line,
                                        column=col,
                                        snippet=snippet,
                                        original_source=get_node_text(node, code_bytes).strip(),
                                        reconstructed_source=k_val,
                                        discovery_method="AST analysis",
                                        tags=["parameter", "query-parameter"],
                                        extra_data={
                                            "name": k_val,
                                            "param_type": "query",
                                            "endpoint": func_name,
                                            "evidence": snippet,
                                            "caller": func_name,
                                        },
                                    )
                                )

        return findings
