from jsxray.acquisition.encoding import decode_bytes
from jsxray.acquisition.validator import validate_javascript_content


def test_decode_bytes():
    utf8_bytes = "const a = 'hello';".encode("utf-8")
    text, enc = decode_bytes(utf8_bytes)
    assert text == "const a = 'hello';"
    assert enc == "utf-8"

    bom_bytes = b"\xef\xbb\xbflet x = 1;"
    text, enc = decode_bytes(bom_bytes)
    assert text == "let x = 1;"
    assert enc == "utf-8-sig"


def test_validate_javascript_content():
    valid_js = "function add(a, b) { return a + b; }"
    is_valid, err = validate_javascript_content(valid_js, content_type="application/javascript")
    assert is_valid is True
    assert err is None

    html_content = "<!DOCTYPE html><html><body>Error</body></html>"
    is_valid, err = validate_javascript_content(html_content, content_type="text/html")
    assert is_valid is False
    assert "HTML" in err
