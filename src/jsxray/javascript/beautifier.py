"""JavaScript beautifier wrapper for JSXRay."""

import jsbeautifier


def beautify_javascript(code: str) -> str:
    """Beautifies minified JavaScript source code for better readability."""
    if not code or not code.strip():
        return ""
    try:
        opts = jsbeautifier.default_options()
        opts.indent_size = 2
        opts.space_in_empty_paren = False
        opts.max_preserve_newlines = 2
        opts.preserve_newlines = True
        opts.wrap_line_length = 120
        return jsbeautifier.beautify(code, opts)
    except Exception:
        # If beautification fails, return original code safely
        return code
