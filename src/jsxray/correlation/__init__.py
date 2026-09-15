"""Correlation module for JSXRay."""

from jsxray.correlation.correlate import CorrelationEngine
from jsxray.correlation.deduplicate import deduplicate_findings
from jsxray.correlation.normalize import Normalizer

__all__ = ["CorrelationEngine", "deduplicate_findings", "Normalizer"]
