"""JavaScript source representation for JSXRay."""

from dataclasses import dataclass, field
import hashlib
from typing import Any, List, Optional


@dataclass
class JavaScriptSource:
    identifier: str
    original_code: str
    beautified_code: Optional[str] = None
    file_path: Optional[str] = None
    url: Optional[str] = None
    size_bytes: int = 0
    content_hash: str = ""
    encoding: str = "utf-8"
    is_valid_js: bool = True
    ast_root: Optional[Any] = None
    parse_error: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.size_bytes and self.original_code:
            self.size_bytes = len(self.original_code.encode(self.encoding, errors="replace"))
        if not self.content_hash and self.original_code:
            self.content_hash = hashlib.sha256(self.original_code.encode("utf-8", errors="replace")).hexdigest()

    @property
    def effective_code(self) -> str:
        return self.beautified_code if self.beautified_code else self.original_code

    def to_dict(self) -> dict:
        return {
            "identifier": self.identifier,
            "file_path": self.file_path,
            "url": self.url,
            "size_bytes": self.size_bytes,
            "content_hash": self.content_hash,
            "encoding": self.encoding,
            "is_valid_js": self.is_valid_js,
            "has_ast": self.ast_root is not None,
            "parse_error": self.parse_error,
            "warnings_count": len(self.warnings),
            "errors_count": len(self.errors),
        }
