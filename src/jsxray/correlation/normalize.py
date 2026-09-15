"""Normalization utilities for JSXRay findings."""

import re
from urllib.parse import unquote, urlparse, urlunparse


class Normalizer:
    """Conservatively normalizes URLs, paths, and dynamic identifier segments."""

    # Matches dynamic numerical IDs (/users/123 -> /users/{id}) and UUIDs
    NUMERIC_ID_SEGMENT = re.compile(r"/([0-9]{2,})(?=/|$)", re.I)
    UUID_SEGMENT = re.compile(r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=/|$)", re.I)
    HEX_HASH_SEGMENT = re.compile(r"/([0-9a-f]{24,64})(?=/|$)", re.I)

    @classmethod
    def normalize_endpoint(cls, endpoint: str) -> str:
        """Normalizes an endpoint path or URL by standardizing dynamic identifier segments."""
        if not endpoint:
            return ""

        val = endpoint.strip()
        # Decode safe URL escapes
        val = unquote(val)

        # Replace UUIDs
        val = cls.UUID_SEGMENT.sub(r"/{uuid}", val)
        # Replace long hex hashes
        val = cls.HEX_HASH_SEGMENT.sub(r"/{hash}", val)
        # Replace numeric IDs
        val = cls.NUMERIC_ID_SEGMENT.sub(r"/{id}", val)

        # Standardize multiple slashes
        val = re.sub(r"(?<!:)//+", "/", val)

        return val

    @classmethod
    def normalize_host(cls, host: str) -> str:
        """Standardizes host names."""
        if not host:
            return ""
        return host.strip().lower().rstrip(".")
