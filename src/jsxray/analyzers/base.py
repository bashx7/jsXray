"""Base analyzer interface for JSXRay."""

from abc import ABC, abstractmethod
from typing import List
from jsxray.javascript.reconstruction import StaticReconstructor
from jsxray.models.finding import Finding
from jsxray.models.source import JavaScriptSource


class BaseAnalyzer(ABC):
    """Abstract base class for all JSXRay static intelligence analyzers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the analyzer."""
        pass

    @abstractmethod
    def analyze(self, source: JavaScriptSource, reconstructor: StaticReconstructor) -> List[Finding]:
        """Performs static analysis on a JavaScript source and returns discovered findings."""
        pass
