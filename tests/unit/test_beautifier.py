from jsxray.javascript.beautifier import beautify_javascript


def test_beautify_javascript():
    minified = "const a=1;function f(x){return x+a;}"
    beautified = beautify_javascript(minified)
    assert "\n" in beautified
    assert "function f(x)" in beautified
