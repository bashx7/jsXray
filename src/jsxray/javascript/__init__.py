"""JavaScript processing module for JSXRay."""

from jsxray.javascript.beautifier import beautify_javascript
from jsxray.javascript.fallback import FallbackAnalyzer
from jsxray.javascript.parser import JSParser
from jsxray.javascript.reconstruction import StaticReconstructor

__all__ = [
    "beautify_javascript",
    "FallbackAnalyzer",
    "JSParser",
    "StaticReconstructor",
]
