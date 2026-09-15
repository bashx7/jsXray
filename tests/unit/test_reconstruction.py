from jsxray.javascript.parser import JSParser
from jsxray.javascript.reconstruction import StaticReconstructor
from jsxray.models.finding import Confidence


def test_constant_propagation_and_concatenation():
    code = """
    const API = "https://api.example.com";
    const PATH = "/users/";
    const endpoint = API + PATH + userId;
    """
    parser = JSParser()
    tree, _ = parser.parse(code)
    reconstructor = StaticReconstructor(tree.root_node, code)

    # Reconstructor should have collected API and PATH
    assert reconstructor.constants.get("API") == "https://api.example.com"
    assert reconstructor.constants.get("PATH") == "/users/"


def test_escape_sequences():
    escaped = r"https\x3a\x2f\x2fapi\u002eexample\u002ecom\x2fusers"
    decoded = StaticReconstructor.decode_escapes(escaped)
    assert decoded == "https://api.example.com/users"


def test_safe_base64_decode():
    b64 = "YWRtaW46cGFzc3dvcmQxMjM="  # admin:password123
    decoded = StaticReconstructor.safe_base64_decode(b64)
    assert decoded == "admin:password123"
