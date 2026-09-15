"""JavaScript validation engine for JSXRay."""

import re
from typing import Optional, Tuple

JS_MIME_TYPES = {
    "application/javascript",
    "application/x-javascript",
    "text/javascript",
    "text/ecmascript",
    "application/ecmascript",
    "application/json",
    "text/plain",
}

NON_JS_PATTERNS = [
    re.compile(r"^\s*<!DOCTYPE\s+html", re.IGNORECASE),
    re.compile(r"^\s*<html\b", re.IGNORECASE),
    re.compile(r"^\s*<\?xml\b", re.IGNORECASE),
]

JS_TOKEN_PATTERNS = [
    re.compile(r"\b(function|const|let|var|return|export|import|class|async|await|typeof|void|null|undefined|true|false)\b"),
    re.compile(r"[;\{\}\(\)\[\]=>]"),
    re.compile(r"\b(window|document|console|fetch|axios|webpackJsonp|self)\b"),
]


def validate_javascript_content(
    content: str,
    content_type: str = "",
    url: str = "",
    filename: str = "",
) -> Tuple[bool, Optional[str]]:
    """Validates whether given content is valid JavaScript using multiple heuristic signals."""
    if not content or not content.strip():
        return False, "Empty content"

    stripped = content.strip()

    # Check for HTML/XML response
    for pattern in NON_JS_PATTERNS:
        if pattern.search(stripped[:500]):
            return False, "Response is HTML or XML document, not JavaScript"

    # Check for binary data
    if "\x00" in stripped[:1024]:
        return False, "Response contains binary null bytes"

    # Check extension
    path_check = (url or filename).lower()
    is_js_extension = any(path_check.endswith(ext) for ext in [".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"])

    # Check mime type
    mime_base = content_type.split(";")[0].strip().lower() if content_type else ""
    is_js_mime = mime_base in JS_MIME_TYPES

    # Token match count
    token_matches = sum(1 for p in JS_TOKEN_PATTERNS if p.search(stripped[:2000]))

    if is_js_extension or is_js_mime or token_matches >= 2:
        return True, None

    # Default heuristic: if it has common JS symbols and keywords
    if token_matches >= 1 and not stripped.startswith("<"):
        return True, None

    return False, "Content does not appear to be JavaScript"
