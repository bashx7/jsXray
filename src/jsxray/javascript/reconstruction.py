"""Safe static JavaScript reconstruction engine for JSXRay."""

import base64
import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote
from tree_sitter import Node
from jsxray.javascript.ast_utils import (
    extract_string_literal,
    get_node_text,
    walk_tree,
)
from jsxray.models.finding import Confidence


class StaticReconstructor:
    def __init__(self, root_node: Optional[Node], code: str) -> None:
        self.root_node = root_node
        self.code = code
        self.code_bytes = code.encode("utf-8", errors="replace")
        self.constants: Dict[str, str] = {}
        if root_node:
            self._collect_constants()

    def _collect_constants(self) -> None:
        """Collects top-level and module-level constant variable assignments."""
        if not self.root_node:
            return
        for node in walk_tree(self.root_node):
            if node.type in ("variable_declarator", "lexical_declaration"):
                name_node = node.child_by_field_name("name")
                value_node = node.child_by_field_name("value")
                if name_node and value_node:
                    var_name = get_node_text(name_node, self.code_bytes).strip()
                    resolved, _, _ = self.resolve_expression(value_node)
                    if resolved is not None and isinstance(resolved, str):
                        self.constants[var_name] = resolved

            # Assignment expressions like API = "https://..."
            elif node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left and right and left.type == "identifier":
                    var_name = get_node_text(left, self.code_bytes).strip()
                    resolved, _, _ = self.resolve_expression(right)
                    if resolved is not None and isinstance(resolved, str):
                        self.constants[var_name] = resolved

    def resolve_expression(self, node: Optional[Node]) -> Tuple[Optional[str], List[str], Confidence]:
        """Statically evaluates an AST expression node."""
        if not node:
            return None, [], Confidence.LOW

        node_type = node.type
        transformations: List[str] = []

        # String literals
        if node_type in ("string", "string_fragment"):
            val = extract_string_literal(node, self.code_bytes)
            if val is not None:
                decoded_val = self.decode_escapes(val)
                if decoded_val != val:
                    transformations.append("escape decoding")
                return decoded_val, transformations, Confidence.HIGH

        # Identifier (check constant propagation)
        if node_type == "identifier":
            ident_name = get_node_text(node, self.code_bytes).strip()
            if ident_name in self.constants:
                transformations.append("constant propagation")
                return self.constants[ident_name], transformations, Confidence.HIGH
            return f"{{{ident_name}}}", ["variable placeholder"], Confidence.MEDIUM

        # Template string (e.g. `https://${host}/api/${userId}`)
        if node_type == "template_string":
            parts: List[str] = []
            has_dynamic = False
            for child in node.children:
                if child.type in ("string_fragment", "escape_sequence"):
                    parts.append(get_node_text(child, self.code_bytes))
                elif child.type == "template_substitution":
                    has_dynamic = True
                    # The substitution expression is the child inside ${ ... }
                    expr_node = None
                    for sub in child.children:
                        if sub.type not in ("${", "}"):
                            expr_node = sub
                            break
                    if expr_node:
                        sub_val, sub_trans, _ = self.resolve_expression(expr_node)
                        transformations.extend(sub_trans)
                        parts.append(sub_val if sub_val is not None else "{var}")
                    else:
                        parts.append("{var}")
            transformations.append("template literal")
            conf = Confidence.MEDIUM if has_dynamic else Confidence.HIGH
            return "".join(parts), transformations, conf

        # Binary expression (e.g. a + b + c)
        if node_type == "binary_expression":
            op_node = node.child_by_field_name("operator")
            op = get_node_text(op_node, self.code_bytes).strip() if op_node else ""
            if op == "+":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                left_val, left_trans, left_conf = self.resolve_expression(left)
                right_val, right_trans, right_conf = self.resolve_expression(right)
                transformations.extend(left_trans)
                transformations.extend(right_trans)
                transformations.append("string concatenation")

                if left_val is not None and right_val is not None:
                    conf = Confidence.HIGH if (left_conf == Confidence.HIGH and right_conf == Confidence.HIGH) else Confidence.MEDIUM
                    return f"{left_val}{right_val}", transformations, conf
                elif left_val is not None:
                    return f"{left_val}{{param}}", transformations, Confidence.LOW
                elif right_val is not None:
                    return f"{{param}}{right_val}", transformations, Confidence.LOW

        # Member expression (e.g. config.apiUrl or process.env.API_URL)
        if node_type == "member_expression":
            full_text = get_node_text(node, self.code_bytes).strip()
            # If known constant
            if full_text in self.constants:
                transformations.append("constant propagation")
                return self.constants[full_text], transformations, Confidence.HIGH
            prop = node.child_by_field_name("property")
            prop_name = get_node_text(prop, self.code_bytes).strip() if prop else "prop"
            return f"{{{prop_name}}}", ["property placeholder"], Confidence.LOW

        # Fallback: raw literal text if simple
        raw_text = get_node_text(node, self.code_bytes).strip()
        if raw_text.startswith(('"', "'", "`")) and raw_text.endswith(('"', "'", "`")):
            return raw_text[1:-1], transformations, Confidence.HIGH

        return None, [], Confidence.LOW

    @staticmethod
    def decode_escapes(text: str) -> str:
        """Decodes JS escape sequences (Unicode escapes \\uXXXX, hex \\xXX, octal, newline, etc.)."""
        if not text:
            return ""
        try:
            # Handle unicode escapes \uXXXX and \xXX
            text = re.sub(
                r"\\u([0-9a-fA-F]{4})",
                lambda m: chr(int(m.group(1), 16)),
                text,
            )
            text = re.sub(
                r"\\x([0-9a-fA-F]{2})",
                lambda m: chr(int(m.group(1), 16)),
                text,
            )
            # Standard escapes
            text = (
                text.replace(r"\n", "\n")
                .replace(r"\t", "\t")
                .replace(r"\r", "\r")
                .replace(r"\/", "/")
                .replace(r'\"', '"')
                .replace(r"\'", "'")
                .replace(r"\\", "\\")
            )
        except Exception:
            pass
        return text

    @staticmethod
    def safe_base64_decode(data: str) -> Optional[str]:
        """Safely checks and decodes valid Base64 encoded strings."""
        if not data or len(data) < 8 or len(data) % 4 != 0:
            return None
        # Must only contain Base64 chars
        if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", data):
            return None
        try:
            decoded_bytes = base64.b64decode(data, validate=True)
            # Only return if mostly printable ASCII / UTF-8
            decoded_str = decoded_bytes.decode("utf-8")
            if sum(1 for c in decoded_str if c.isprintable()) / max(1, len(decoded_str)) >= 0.85:
                return decoded_str
        except Exception:
            pass
        return None

    @staticmethod
    def safe_url_decode(data: str) -> Optional[str]:
        """Decodes URL-encoded substrings."""
        if not data or "%" not in data:
            return None
        try:
            decoded = unquote(data)
            if decoded != data:
                return decoded
        except Exception:
            pass
        return None

    @staticmethod
    def safe_json_decode(data: str) -> Optional[Any]:
        """Safely parses JSON strings without evaluation."""
        if not data or not (data.startswith("{") or data.startswith("[")):
            return None
        try:
            return json.loads(data)
        except Exception:
            return None
