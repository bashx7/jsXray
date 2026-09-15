"""Utility helper functions for JSXRay."""

import math
import re
from typing import Optional
from urllib.parse import urlparse, urlunparse


def calculate_shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    char_counts = {}
    for char in data:
        char_counts[char] = char_counts.get(char, 0) + 1
    for count in char_counts.values():
        p_x = count / length
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    return entropy


def mask_secret(secret: str, prefix_keep: int = 4, suffix_keep: int = 2) -> str:
    """Safely masks a secret while preserving prefix/suffix for identification."""
    if not secret:
        return ""
    length = len(secret)
    if length <= 6:
        return "*" * length
    prefix = secret[:prefix_keep]
    suffix = secret[-suffix_keep:] if suffix_keep > 0 else ""
    mask_len = max(6, length - prefix_keep - suffix_keep)
    return f"{prefix}{'*' * mask_len}{suffix}"


def sanitize_snippet(snippet: str, max_length: int = 200) -> str:
    """Cleans and truncates a source code snippet for reporting."""
    if not snippet:
        return ""
    cleaned = re.sub(r"\s+", " ", snippet).strip()
    if len(cleaned) > max_length:
        return cleaned[: max_length - 3] + "..."
    return cleaned


def extract_host(url_or_domain: str) -> Optional[str]:
    """Extracts clean hostname from a URL or string."""
    if not url_or_domain:
        return None
    url_or_domain = url_or_domain.strip()
    if "://" not in url_or_domain:
        url_or_domain = "https://" + url_or_domain
    try:
        parsed = urlparse(url_or_domain)
        host = parsed.hostname
        if host:
            return host.lower()
    except Exception:
        pass
    return None


def normalize_url(url: str) -> str:
    """Normalizes URL by stripping fragments and standardizing port/slashes."""
    if not url:
        return ""
    url = url.strip()
    try:
        parsed = urlparse(url)
        # Remove fragment, normalize scheme and netloc to lowercase
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path or "/"
        return urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))
    except Exception:
        return url
