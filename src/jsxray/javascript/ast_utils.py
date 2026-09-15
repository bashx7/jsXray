"""AST utility and traversal helpers for Tree-sitter in JSXRay."""

from typing import Any, Dict, Generator, List, Optional, Set, Tuple
from tree_sitter import Node


def get_node_text(node: Node, code_bytes: bytes) -> str:
    """Extracts decoded text string corresponding to an AST node."""
    if not node:
        return ""
    return code_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def walk_tree(root: Node) -> Generator[Node, None, None]:
    """Iteratively traverses all AST nodes in depth-first pre-order."""
    if not root:
        return
    stack = [root]
    while stack:
        current = stack.pop()
        yield current
        for i in range(len(current.children) - 1, -1, -1):
            stack.append(current.children[i])


def find_nodes_by_types(root: Node, target_types: Set[str]) -> List[Node]:
    """Finds all nodes matching the given types."""
    results = []
    for node in walk_tree(root):
        if node.type in target_types:
            results.append(node)
    return results


def get_node_line_col(node: Node) -> Tuple[int, int]:
    """Returns 1-indexed (line, column) for an AST node."""
    if not node:
        return 1, 1
    return node.start_point[0] + 1, node.start_point[1] + 1


def get_node_snippet(node: Node, code_lines: List[str], code_bytes: Optional[bytes] = None, max_chars: int = 240) -> str:
    """Extracts a readable, bounded code snippet around an AST node without exploding on minified single-line files."""
    if not node:
        return ""

    if code_bytes:
        start = max(0, node.start_byte - 40)
        end = min(len(code_bytes), node.end_byte + 60)
        raw_slice = code_bytes[start:end].decode("utf-8", errors="replace").strip()
        # Clean multiple spaces/newlines
        cleaned = " ".join(raw_slice.split())
        if len(cleaned) > max_chars:
            return cleaned[:max_chars - 3] + "..."
        return cleaned

    if code_lines:
        start_row = node.start_point[0]
        if 0 <= start_row < len(code_lines):
            line_str = code_lines[start_row].strip()
            if len(line_str) > max_chars:
                col = node.start_point[1]
                c_start = max(0, col - 40)
                c_end = min(len(line_str), col + max_chars - 40)
                return "..." + line_str[c_start:c_end].strip() + "..."
            return line_str

    return ""


def extract_string_literal(node: Node, code_bytes: bytes) -> Optional[str]:
    """Extracts the string contents from a string literal node, removing quotes."""
    if not node:
        return None
    if node.type in ("string", "string_fragment", "template_string"):
        text = get_node_text(node, code_bytes)
        if (text.startswith('"') and text.endswith('"')) or (text.startswith("'") and text.endswith("'")):
            return text[1:-1]
        if text.startswith("`") and text.endswith("`"):
            return text[1:-1]
        return text
    return None


def get_object_properties(obj_node: Node, code_bytes: bytes) -> Dict[str, Node]:
    """Extracts key -> value node mapping from an object literal node."""
    props: Dict[str, Node] = {}
    if not obj_node or obj_node.type != "object":
        return props

    for child in obj_node.children:
        if child.type == "pair":
            key_node = child.child_by_field_name("key")
            value_node = child.child_by_field_name("value")
            if key_node and value_node:
                key_text = get_node_text(key_node, code_bytes).strip("\"'`")
                props[key_text] = value_node
    return props
