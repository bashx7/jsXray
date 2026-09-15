"""Secret detection subpackage for JSXRay."""

from jsxray.secrets.classifier import SecretClassifier
from jsxray.secrets.confidence import ConfidenceScorer
from jsxray.secrets.definitions import get_all_detectors
from jsxray.secrets.engine import SecretDetectionEngine, mask_secret
from jsxray.secrets.generic import GenericSecretDetector
from jsxray.secrets.schema import SecretCategory, SecretDetector

__all__ = [
    "SecretCategory",
    "SecretDetector",
    "SecretClassifier",
    "ConfidenceScorer",
    "GenericSecretDetector",
    "SecretDetectionEngine",
    "get_all_detectors",
    "mask_secret",
]
