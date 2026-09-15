"""Encoding detection and decoding utilities for JSXRay."""

from typing import Tuple


def decode_bytes(data: bytes, declared_charset: str = "") -> Tuple[str, str]:
    """Safely decodes raw bytes into text using multi-strategy encoding detection."""
    if not data:
        return "", "utf-8"

    # Check for byte order mark (BOM)
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", errors="replace"), "utf-8-sig"
    if data.startswith(b"\xff\xfe"):
        return data[2:].decode("utf-16-le", errors="replace"), "utf-16-le"
    if data.startswith(b"\xfe\xff"):
        return data[2:].decode("utf-16-be", errors="replace"), "utf-16-be"

    # Try declared charset if present
    if declared_charset:
        try:
            return data.decode(declared_charset), declared_charset
        except (UnicodeDecodeError, LookupError):
            pass

    # Try standard encodings in priority order
    for encoding in ["utf-8", "latin-1", "windows-1252", "iso-8859-1"]:
        try:
            decoded = data.decode(encoding)
            return decoded, encoding
        except UnicodeDecodeError:
            continue

    # Fallback to UTF-8 with replacement characters
    return data.decode("utf-8", errors="replace"), "utf-8-fallback"
