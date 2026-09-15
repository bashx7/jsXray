"""Negative classifier and false-positive filter for JSXRay secret detection."""

import re
from typing import Optional, Tuple


class SecretClassifier:
    """Classifies values and filters out non-secret false positives."""

    # Static asset and code file extensions
    FILE_EXTENSIONS = (
        ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
        ".css", ".scss", ".sass", ".less",
        ".map", ".json", ".vue", ".html", ".htm",
        ".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".wasm", ".txt", ".md", ".pdf", ".zip", ".tar.gz",
    )

    # Static asset, route and framework directory paths
    PATH_INDICATORS = (
        "/cdn/", "/assets/", "/static/", "/chunks/", "/node_modules/",
        "/dist/", "/build/", "/public/", "/src/", "/components/",
        "/modules/", "/locales/", "/i18n/", "/fonts/", "/images/",
        "/icons/", "/media/", "/styles/", "/vendor/", "/_next/",
        "/_nuxt/", "/wp-content/", "/wp-includes/", "routes/",
    )

    UUID_REGEX = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
    HEX_HASH_REGEX = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$", re.I)
    ASSET_HASH_REGEX = re.compile(r"-[0-9a-z]{7,12}\.(?:js|css|chunk|bundle)$", re.I)
    CSS_CLASS_REGEX = re.compile(r"^(?:(?:flex|grid|p-|m-|text-|bg-|border-|hover:|focus:|rounded|w-|h-|sm:|md:|lg:|dark:)[a-zA-Z0-9_\-:\.]*\s*){2,}$")
    SCHEMA_URL_REGEX = re.compile(r"^https?://(?:schema\.org|www\.w3\.org|xmlns\.com)/?", re.I)
    LOCALIZATION_REGEX = re.compile(r"^[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_\-]+){2,}$")

    DUMMY_VALUES = {
        "your_api_key", "your_token", "your_secret", "your_api_key_here",
        "api_key_here", "insert_key_here", "enter_token_here", "example_token",
        "dummy_token", "placeholder", "changeme", "todo_set_token",
        "00000000000000000000000000000000", "12345678901234567890123456789012",
        "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    }

    @classmethod
    def is_false_positive(cls, value: str, context: str = "") -> Tuple[bool, Optional[str]]:
        """Determines if a candidate string is a false positive (route, file, asset, UUID, etc.)."""
        if not value:
            return True, "Empty value"

        val_clean = value.strip()
        val_lower = val_clean.lower()

        # 1. Check known file extensions
        if any(val_lower.endswith(ext) for ext in cls.FILE_EXTENSIONS):
            return True, "Static asset or code filename"

        # 2. Check path indicators (e.g. routes/admin.access-tokens or /cdn/assets/...)
        if any(p in val_lower for p in cls.PATH_INDICATORS):
            return True, "Asset, module, or route path"

        # 3. Check asset bundle hash filenames (e.g. access-tokens-huqqaia3.js)
        if cls.ASSET_HASH_REGEX.search(val_lower):
            return True, "Hashed asset filename"

        # 4. Check UUIDs
        if cls.UUID_REGEX.match(val_clean):
            return True, "UUID identifier"

        # 5. Check pure standalone hex hashes without credential assignment
        if cls.HEX_HASH_REGEX.match(val_clean):
            ctx_lower = context.lower()
            if not any(k in ctx_lower for k in ["api_key", "apikey", "secret", "private_key", "token", "password", "auth"]):
                return True, "Standalone hexadecimal hash"

        # 6. Check Schema.org / W3C URLs
        if cls.SCHEMA_URL_REGEX.match(val_clean):
            return True, "Schema or standard namespace URL"

        # 7. Check CSS classes / Tailwind strings
        if cls.CSS_CLASS_REGEX.match(val_clean):
            return True, "CSS stylesheet class sequence"

        # 8. Check localization / dot-notation strings (e.g. settings.access-tokens.label)
        if cls.LOCALIZATION_REGEX.match(val_clean):
            segments = val_clean.split(".")
            if not val_clean.startswith("SG.") and not val_clean.startswith("eyJ") and not val_clean.startswith("AIza"):
                # Localization keys typically consist of short word segments (all < 20 chars)
                if all(len(seg) <= 20 for seg in segments) and "/" not in val_clean and " " not in val_clean:
                    return True, "Localization key or property path"

        # 9. Check obvious dummy placeholders
        if val_lower in cls.DUMMY_VALUES:
            return True, "Placeholder dummy value"

        # 10. Check if string contains spaces and is English prose
        if val_clean.count(" ") >= 3:
            return True, "Natural language sentence"

        return False, None
