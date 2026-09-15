"""Contextual generic secret detector for JSXRay.

Analyzes AST assignments, object properties, and HTTP headers to detect high-entropy credentials
while rejecting routes, static asset paths, filenames, and localization keys.
"""

import re
from typing import List, Optional, Tuple

from jsxray.secrets.classifier import SecretClassifier
from jsxray.secrets.confidence import ConfidenceScorer
from jsxray.secrets.schema import SecretCategory


class GenericSecretDetector:
    """Detects credentials in context of variables, object properties, and headers."""

    # Variable or key names that explicitly signal credential storage
    CREDENTIAL_KEY_PATTERNS = [
        re.compile(r"^(?:api[_\-]?key|apikey)$", re.I),
        re.compile(r"^(?:secret[_\-]?key|secretkey|app[_\-]?secret|client[_\-]?secret)$", re.I),
        re.compile(r"^(?:auth[_\-]?token|access[_\-]?token|jwt[_\-]?token|bearer[_\-]?token)$", re.I),
        re.compile(r"^(?:private[_\-]?key|privkey|encryption[_\-]?key)$", re.I),
        re.compile(r"^(?:password|passwd|db[_\-]?pass|database[_\-]?password)$", re.I),
        re.compile(r"^(?:x[_\-]?api[_\-]?key|x[_\-]?auth[_\-]?token)$", re.I),
    ]

    # Regex for Bearer tokens in headers or string literals
    BEARER_REGEX = re.compile(
        r"""(?:Bearer|bearer)\s+([a-zA-Z0-9_\-\.]{20,256})""",
        re.I,
    )

    # Regex for assignment or object property patterns in raw text / AST snippet
    ASSIGNMENT_REGEX = re.compile(
        r"""(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*['"`]([a-zA-Z0-9_\-\.\+\/=]{16,256})['"`]""",
    )
    OBJECT_PROP_REGEX = re.compile(
        r"""['"`]?([a-zA-Z0-9_\-$]+)['"`]?\s*:\s*['"`]([a-zA-Z0-9_\-\.\+\/=]{16,256})['"`]""",
    )

    @classmethod
    def is_credential_identifier(cls, key_name: str) -> bool:
        """Checks if a variable or property identifier matches credential naming patterns."""
        if not key_name:
            return False
        k = key_name.strip()
        return any(p.match(k) for p in cls.CREDENTIAL_KEY_PATTERNS)

    @classmethod
    def analyze_candidate(
        cls,
        key_name: str,
        value: str,
        snippet: str = "",
    ) -> Optional[Tuple[str, str, float, str]]:
        """
        Validates a candidate key-value pair.
        Returns (secret_type, confidence_level, score, reason) if it is a valid generic secret,
        or None if rejected.
        """
        if not value or len(value) < 16 or len(value) > 256:
            return None

        # 1. Run negative classifier to filter out routes, filenames, asset paths, etc.
        is_fp, reason = SecretClassifier.is_false_positive(value, context=key_name + " " + snippet)
        if is_fp:
            return None

        # 2. Variable or key name must match credential naming pattern
        if not cls.is_credential_identifier(key_name):
            return None

        # 3. Shannon entropy must be at least 3.0 for generic secrets (entropy alone doesn't suffice, but required here)
        entropy = ConfidenceScorer.calculate_entropy(value)
        if entropy < 3.0:
            return None

        # 4. Score confidence
        level, score, reasons = ConfidenceScorer.evaluate(
            value=value,
            detector=None,
            context=f"{key_name} = '{value}' in {snippet}",
            is_generic=True,
        )

        if level == "Reject":
            return None

        secret_type = f"Generic {key_name.replace('_', ' ').title()}"
        return secret_type, level, score, reasons
