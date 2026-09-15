"""API and HTTP Request endpoint analyzer for JSXRay."""

from typing import List, Optional, Tuple
from tree_sitter import Node
from jsxray.analyzers.base import BaseAnalyzer
from jsxray.javascript.ast_utils import (
    get_node_line_col,
    get_node_snippet,
    get_node_text,
    get_object_properties,
    walk_tree,
)
from jsxray.javascript.reconstruction import StaticReconstructor
from jsxray.models.finding import Confidence, Finding, FindingStatus, FindingType
from jsxray.models.source import JavaScriptSource


class ApiAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "api"

    def analyze(self, source: JavaScriptSource, reconstructor: StaticReconstructor) -> List[Finding]:
        findings: List[Finding] = []
        if not source.ast_root:
            return findings

        code_bytes = source.effective_code.encode("utf-8", errors="replace")
        code_lines = source.effective_code.splitlines()

        for node in walk_tree(source.ast_root):
            if node.type == "call_expression":
                finding = self._check_call_expression(node, source, reconstructor, code_bytes, code_lines)
                if finding:
                    findings.append(finding)

            elif node.type == "new_expression":
                finding = self._check_new_expression(node, source, reconstructor, code_bytes, code_lines)
                if finding:
                    findings.append(finding)

        return findings

    def _check_call_expression(
        self,
        node: Node,
        source: JavaScriptSource,
        reconstructor: StaticReconstructor,
        code_bytes: bytes,
        code_lines: List[str],
    ) -> Optional[Finding]:
        function_node = node.child_by_field_name("function")
        args_node = node.child_by_field_name("arguments")
        if not function_node or not args_node:
            return None

        func_text = get_node_text(function_node, code_bytes).strip()
        args = [c for c in args_node.children if c.type not in ("(", ")", ",")]
        if not args:
            return None

        method: Optional[str] = None
        endpoint_node: Optional[Node] = None
        req_type = "generic"

        # 1. fetch(url, options)
        if func_text in ("fetch", "window.fetch"):
            req_type = "fetch"
            endpoint_node = args[0]
            method = "GET"
            if len(args) > 1 and args[1].type == "object":
                props = get_object_properties(args[1], code_bytes)
                if "method" in props:
                    method_val, _, _ = reconstructor.resolve_expression(props["method"])
                    if method_val:
                        method = method_val.upper()

        # 2. axios methods
        elif func_text.startswith("axios.") or func_text.startswith("http.") or func_text.startswith("apiClient."):
            prop = func_text.split(".")[-1].lower()
            if prop in ("get", "post", "delete", "put", "patch", "head", "options"):
                req_type = "axios"
                method = prop.upper()
                endpoint_node = args[0]
            elif prop == "request" and args[0].type == "object":
                req_type = "axios"
                props = get_object_properties(args[0], code_bytes)
                if "url" in props:
                    endpoint_node = props["url"]
                if "method" in props:
                    method_val, _, _ = reconstructor.resolve_expression(props["method"])
                    method = method_val.upper() if method_val else "GET"

        # 3. axios(url, config)
        elif func_text == "axios":
            req_type = "axios"
            if args[0].type == "object":
                props = get_object_properties(args[0], code_bytes)
                if "url" in props:
                    endpoint_node = props["url"]
                if "method" in props:
                    method_val, _, _ = reconstructor.resolve_expression(props["method"])
                    method = method_val.upper() if method_val else "GET"
            else:
                endpoint_node = args[0]
                method = "GET"
                if len(args) > 1 and args[1].type == "object":
                    props = get_object_properties(args[1], code_bytes)
                    if "method" in props:
                        method_val, _, _ = reconstructor.resolve_expression(props["method"])
                        if method_val:
                            method = method_val.upper()

        # 4. xhr.open("METHOD", url)
        elif func_text.endswith(".open") and len(args) >= 2:
            req_type = "xhr"
            m_val, _, _ = reconstructor.resolve_expression(args[0])
            if m_val and m_val.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                method = m_val.upper()
                endpoint_node = args[1]

        # 5. jQuery: $.ajax(), $.get(), $.post()
        elif func_text in ("$.ajax", "jQuery.ajax") and args[0].type == "object":
            req_type = "jquery"
            props = get_object_properties(args[0], code_bytes)
            if "url" in props:
                endpoint_node = props["url"]
            m_node = props.get("type") or props.get("method")
            if m_node:
                m_val, _, _ = reconstructor.resolve_expression(m_node)
                method = m_val.upper() if m_val else "GET"
            else:
                method = "GET"

        elif func_text in ("$.get", "jQuery.get"):
            req_type = "jquery"
            method = "GET"
            endpoint_node = args[0]

        elif func_text in ("$.post", "jQuery.post"):
            req_type = "jquery"
            method = "POST"
            endpoint_node = args[0]

        if not endpoint_node:
            return None

        raw_endpoint_text = get_node_text(endpoint_node, code_bytes).strip()
        resolved_url, transformations, confidence = reconstructor.resolve_expression(endpoint_node)

        if not resolved_url:
            resolved_url = raw_endpoint_text

        if resolved_url.startswith(('"', "'", "`")) and resolved_url.endswith(('"', "'", "`")):
            resolved_url = resolved_url[1:-1]

        if not (resolved_url.startswith(("/", "http://", "https://", "{")) or "/api" in resolved_url or "/" in resolved_url):
            return None

        line, col = get_node_line_col(node)
        snippet = get_node_snippet(node, code_lines, code_bytes=code_bytes)
        call_text = get_node_text(node, code_bytes).strip()
        formatted_value = f"{method or 'GET'} {resolved_url}"

        return Finding(
            type=FindingType.API_ENDPOINT,
            value=formatted_value,
            normalized_value=resolved_url,
            confidence=confidence,
            status=FindingStatus.DETECTED,
            source_file=source.file_path,
            source_url=source.url,
            line=line,
            column=col,
            snippet=snippet,
            original_source=call_text,
            reconstructed_source=resolved_url,
            discovery_method="AST analysis",
            tags=["api", req_type, f"method:{method or 'GET'}"],
            extra_data={
                "method": method or "GET",
                "raw_endpoint": raw_endpoint_text,
                "client": req_type,
                "transformations": transformations,
            },
        )

    def _check_new_expression(
        self,
        node: Node,
        source: JavaScriptSource,
        reconstructor: StaticReconstructor,
        code_bytes: bytes,
        code_lines: List[str],
    ) -> Optional[Finding]:
        constructor_node = node.child_by_field_name("constructor")
        args_node = node.child_by_field_name("arguments")
        if not constructor_node or not args_node:
            return None

        c_name = get_node_text(constructor_node, code_bytes).strip()
        if c_name != "URL":
            return None

        args = [c for c in args_node.children if c.type not in ("(", ")", ",")]
        if not args:
            return None

        resolved_url, trans, conf = reconstructor.resolve_expression(args[0])
        base_url = None
        if len(args) > 1:
            base_url, base_trans, _ = reconstructor.resolve_expression(args[1])
            trans.extend(base_trans)

        full_url = resolved_url or ""
        if base_url and not full_url.startswith("http"):
            full_url = f"{base_url.rstrip('/')}/{full_url.lstrip('/')}"

        line, col = get_node_line_col(node)
        snippet = get_node_snippet(node, code_lines, code_bytes=code_bytes)

        return Finding(
            type=FindingType.API_ENDPOINT,
            value=f"GET {full_url}",
            normalized_value=full_url,
            confidence=conf,
            status=FindingStatus.DETECTED,
            source_file=source.file_path,
            source_url=source.url,
            line=line,
            column=col,
            snippet=snippet,
            original_source=get_node_text(node, code_bytes).strip(),
            reconstructed_source=full_url,
            discovery_method="AST analysis",
            tags=["api", "url-constructor", "method:GET"],
            extra_data={"method": "GET", "client": "URL", "transformations": trans},
        )
