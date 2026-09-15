"""Input module for JSXRay."""

from jsxray.input.local_files import discover_local_files
from jsxray.input.url_file import parse_url_file

__all__ = ["discover_local_files", "parse_url_file"]
