"""Hashing utilities for JSXRay."""

import hashlib


def sha256_text(text: str) -> str:
    """Returns the SHA256 hex digest of a string."""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def finding_fingerprint(finding_type: str, value: str, normalized_value: str, source_file: str = "") -> str:
    """Generates a consistent deduplication fingerprint for a finding."""
    key = f"{finding_type}:{value.strip()}:{normalized_value.strip()}:{source_file.strip()}"
    return hashlib.md5(key.encode("utf-8", errors="replace")).hexdigest()
