"""Secret Detection Engine orchestrator for JSXRay.

Coordinates 500+ vendor pattern detectors, contextual generic credential detectors,
negative false-positive filters, and multi-signal confidence scoring.
"""

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from jsxray.secrets.classifier import SecretClassifier
from jsxray.secrets.confidence import ConfidenceScorer
from jsxray.secrets.definitions import get_all_detectors
from jsxray.secrets.generic import GenericSecretDetector
from jsxray.secrets.schema import SecretCategory, SecretDetector


def mask_secret(value: str) -> str:
    """Masks secret value for safe display in reports while preserving debuggability."""
    if not value:
        return ""
    length = len(value)
    if length <= 6:
        return "*" * length
    if length <= 12:
        return f"{value[:2]}{'*' * (length - 4)}{value[-2:]}"
    return f"{value[:4]}{'*' * (length - 8)}{value[-4:]}"


def find_line_and_col(content: str, start_index: int) -> Tuple[int, int, str]:
    """Computes 1-indexed line number, column, and bounded code snippet around index."""
    line = content.count("\n", 0, start_index) + 1
    last_nl = content.rfind("\n", 0, start_index)
    col = (start_index - last_nl) if last_nl != -1 else (start_index + 1)

    # Extract bounded snippet around start_index (max 180 chars)
    snippet_start = max(0, start_index - 60)
    snippet_end = min(len(content), start_index + 120)
    snippet = content[snippet_start:snippet_end].replace("\r", " ").replace("\n", " ").strip()

    return line, col, snippet


class SecretDetectionEngine:
    """High-performance orchestrator for secret detection across JS sources."""

    def __init__(self, detectors: Optional[List[SecretDetector]] = None):
        self.detectors: List[SecretDetector] = detectors if detectors is not None else get_all_detectors()

        # Prefix index for fast preliminary filtering when prefixes are defined
        self.prefix_map: Dict[str, List[SecretDetector]] = {}
        for d in self.detectors:
            for pfx in d.prefixes:
                self.prefix_map.setdefault(pfx, []).append(d)

    def scan_content(self, content: str, file_path: str = "") -> List[Dict[str, Any]]:
        """Scans JavaScript file content for structured and generic secrets."""
        if not content:
            return []

        results: List[Dict[str, Any]] = []
        seen_values: Set[Tuple[str, int]] = set()

        # 1. Scan vendor pattern detectors (500+ structured rules)
        for detector in self.detectors:
            for match in detector.pattern.finditer(content):
                # Value could be full match or group 1
                try:
                    val = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                except IndexError:
                    val = match.group(0)

                val = val.strip().strip("'\"`")
                if not val:
                    continue

                start_idx = match.start()
                val_key = (val, start_idx)
                if val_key in seen_values:
                    continue

                # Run negative false positive classification
                line, col, snippet = find_line_and_col(content, start_idx)
                is_fp, fp_reason = SecretClassifier.is_false_positive(val, context=snippet)
                if is_fp:
                    continue

                # Enforce detector min/max lengths
                if len(val) < detector.min_length or len(val) > detector.max_length:
                    continue

                # Enforce detector min entropy if specified
                entropy = ConfidenceScorer.calculate_entropy(val)
                if detector.min_entropy > 0 and entropy < detector.min_entropy:
                    continue

                # Enforce required context if detector requires context keywords
                if detector.required_context:
                    snippet_lower = snippet.lower()
                    keywords = detector.context_keywords if detector.context_keywords else [detector.provider.lower(), detector.detector_id.lower()]
                    if not any(kw.lower() in snippet_lower for kw in keywords):
                        continue

                # Run validator if specified
                if detector.validator and not detector.validator(val):
                    continue

                # Evaluate multi-signal confidence
                confidence_level, score, reason = ConfidenceScorer.evaluate(
                    value=val,
                    detector=detector,
                    context=snippet,
                    is_generic=False,
                )

                if confidence_level == "Reject":
                    continue

                seen_values.add(val_key)
                results.append({
                    "detector_id": detector.detector_id,
                    "provider": detector.provider,
                    "secret_type": detector.secret_type,
                    "category": detector.category.value if isinstance(detector.category, SecretCategory) else str(detector.category),
                    "raw_value": val,
                    "masked_value": mask_secret(val),
                    "confidence": confidence_level,
                    "confidence_score": score,
                    "confidence_reason": reason,
                    "file_path": file_path,
                    "line_number": line,
                    "column": col,
                    "code_snippet": snippet,
                })

        # 2. Contextual generic secret detection (AST assignments / properties / Bearer headers)
        # Scan assignment expressions (const apiKey = "...")
        for match in GenericSecretDetector.ASSIGNMENT_REGEX.finditer(content):
            key_name = match.group(1)
            val = match.group(2).strip().strip("'\"`")
            start_idx = match.start()
            val_key = (val, start_idx)
            if val_key in seen_values:
                continue

            line, col, snippet = find_line_and_col(content, start_idx)
            candidate = GenericSecretDetector.analyze_candidate(key_name, val, snippet)
            if candidate:
                secret_type, conf_level, score, reason = candidate
                seen_values.add(val_key)
                results.append({
                    "detector_id": f"generic_{key_name.lower()}",
                    "provider": "Generic",
                    "secret_type": secret_type,
                    "category": SecretCategory.GENERIC.value,
                    "raw_value": val,
                    "masked_value": mask_secret(val),
                    "confidence": conf_level,
                    "confidence_score": score,
                    "confidence_reason": reason,
                    "file_path": file_path,
                    "line_number": line,
                    "column": col,
                    "code_snippet": snippet,
                })

        # Scan object properties (apiKey: "...")
        for match in GenericSecretDetector.OBJECT_PROP_REGEX.finditer(content):
            key_name = match.group(1)
            val = match.group(2).strip().strip("'\"`")
            start_idx = match.start()
            val_key = (val, start_idx)
            if val_key in seen_values:
                continue

            line, col, snippet = find_line_and_col(content, start_idx)
            candidate = GenericSecretDetector.analyze_candidate(key_name, val, snippet)
            if candidate:
                secret_type, conf_level, score, reason = candidate
                seen_values.add(val_key)
                results.append({
                    "detector_id": f"generic_{key_name.lower()}",
                    "provider": "Generic",
                    "secret_type": secret_type,
                    "category": SecretCategory.GENERIC.value,
                    "raw_value": val,
                    "masked_value": mask_secret(val),
                    "confidence": conf_level,
                    "confidence_score": score,
                    "confidence_reason": reason,
                    "file_path": file_path,
                    "line_number": line,
                    "column": col,
                    "code_snippet": snippet,
                })

        # Scan Bearer tokens in Authorization headers or strings
        for match in GenericSecretDetector.BEARER_REGEX.finditer(content):
            val = match.group(1).strip().strip("'\"`")
            start_idx = match.start()
            val_key = (val, start_idx)
            if val_key in seen_values:
                continue

            line, col, snippet = find_line_and_col(content, start_idx)
            is_fp, _ = SecretClassifier.is_false_positive(val, context=snippet)
            if is_fp:
                continue

            entropy = ConfidenceScorer.calculate_entropy(val)
            if entropy >= 3.8 and len(val) >= 20:
                conf_level, score, reason = ConfidenceScorer.evaluate(
                    value=val,
                    detector=None,
                    context=f"Bearer token in {snippet}",
                    is_generic=True,
                )
                if conf_level != "Reject":
                    seen_values.add(val_key)
                    results.append({
                        "detector_id": "generic_bearer_token",
                        "provider": "Generic",
                        "secret_type": "Bearer Authentication Token",
                        "category": SecretCategory.AUTH.value,
                        "raw_value": val,
                        "masked_value": mask_secret(val),
                        "confidence": conf_level,
                        "confidence_score": score,
                        "confidence_reason": reason,
                        "file_path": file_path,
                        "line_number": line,
                        "column": col,
                        "code_snippet": snippet,
                    })

        return results
