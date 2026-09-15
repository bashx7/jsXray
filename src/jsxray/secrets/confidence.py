"""Confidence scoring engine for JSXRay secret detection."""

import math
from typing import Dict, Optional, Tuple
from jsxray.secrets.schema import SecretDetector


class ConfidenceScorer:
    """Calculates multi-signal confidence ratings (HIGH, MEDIUM, LOW) for secret candidates."""

    @staticmethod
    def calculate_entropy(data: str) -> float:
        """Calculate Shannon entropy for a string."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        freq: Dict[str, int] = {}
        for c in data:
            freq[c] = freq.get(c, 0) + 1
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    @classmethod
    def evaluate(
        cls,
        value: str,
        detector: Optional[SecretDetector] = None,
        context: str = "",
        is_generic: bool = False,
    ) -> Tuple[str, float, str]:
        """
        Calculates confidence level ('High', 'Medium', 'Low', or 'Reject'), numerical score (0-100),
        and explanation reason.
        """
        score = 0.0
        reasons = []

        entropy = cls.calculate_entropy(value)
        val_lower = value.lower()
        ctx_lower = context.lower()

        # 1. Base provider vs generic pattern
        if detector:
            # Matches a specific well-defined vendor pattern
            score += 45.0
            reasons.append(f"Matched vendor signature ({detector.provider})")

            # Check if value starts with a known vendor prefix
            if detector.prefixes and any(value.startswith(pfx) for pfx in detector.prefixes):
                score += 25.0
                reasons.append("Exact vendor prefix match")

            # Run validator if available
            if detector.validator:
                if detector.validator(value):
                    score += 20.0
                    reasons.append("Checksum/structure validator passed")
                else:
                    score -= 40.0
                    reasons.append("Validator checksum failed")

            if detector.confidence_base == "High":
                score += 10.0
            elif detector.confidence_base == "Low":
                score -= 15.0

        else:
            # Generic credential candidate or unindexed pattern
            score += 35.0
            reasons.append("Candidate credential pattern")

        # 2. Contextual evaluation
        cred_keywords = [
            "api_key", "apikey", "secret", "token", "password", "private_key",
            "auth_token", "access_token", "bearer", "client_secret", "x-api-key",
            "x-auth-token", "authorization", "credential", "app_secret",
        ]
        if any(kw in ctx_lower for kw in cred_keywords):
            score += 25.0
            reasons.append("Credential variable/header context")

        # Assignment context: const KEY = "..." or "api_key": "..."
        if any(op in context for op in ["=", ":", "Bearer", "bearer"]):
            score += 10.0

        # 3. Entropy evaluation
        if entropy >= 4.5:
            score += 15.0
            reasons.append(f"High Shannon entropy ({entropy:.2f})")
        elif entropy >= 3.8:
            score += 10.0
            reasons.append(f"Moderate Shannon entropy ({entropy:.2f})")
        elif entropy < 3.0 and not (detector and detector.prefixes):
            score -= 25.0
            reasons.append(f"Low entropy ({entropy:.2f})")

        # 4. Length checks
        if len(value) >= 32:
            score += 5.0
        elif len(value) < 16 and not (detector and detector.prefixes):
            score -= 20.0

        # 5. Negative indicators
        # English prose / spaces
        if " " in value:
            score -= 30.0

        # Cap score between 0 and 100
        score = max(0.0, min(100.0, score))

        if score >= 70.0:
            level = "High"
        elif score >= 50.0:
            level = "Medium"
        elif score >= 30.0:
            level = "Low"
        else:
            level = "Reject"

        return level, score, "; ".join(reasons)
