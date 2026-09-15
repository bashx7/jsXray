"""Tree-sitter JavaScript AST parser for JSXRay."""

from typing import Optional, Tuple
from tree_sitter import Language, Parser, Tree
import tree_sitter_javascript as tsjs


class JSParser:
    def __init__(self) -> None:
        self.language = Language(tsjs.language())
        self.parser = Parser(self.language)

    def parse(self, code: str) -> Tuple[Optional[Tree], Optional[str]]:
        """Parses JavaScript code into a Tree-sitter AST."""
        if not code or not code.strip():
            return None, "Empty code"
        try:
            byte_code = code.encode("utf-8", errors="replace")
            tree = self.parser.parse(byte_code)
            if tree is None:
                return None, "Parser returned null tree"
            return tree, None
        except Exception as e:
            return None, f"Tree-sitter parse error: {e}"
