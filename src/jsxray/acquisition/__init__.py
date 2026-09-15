"""Acquisition module for JSXRay."""

from jsxray.acquisition.downloader import Downloader
from jsxray.acquisition.encoding import decode_bytes
from jsxray.acquisition.validator import validate_javascript_content

__all__ = ["Downloader", "decode_bytes", "validate_javascript_content"]
