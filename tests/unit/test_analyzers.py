from jsxray.analyzers.api import ApiAnalyzer
from jsxray.analyzers.authentication import AuthenticationAnalyzer
from jsxray.analyzers.credentials import CredentialAnalyzer
from jsxray.analyzers.dangerous_js import DangerousJsAnalyzer
from jsxray.analyzers.graphql import GraphQLAnalyzer
from jsxray.analyzers.hosts import HostAnalyzer
from jsxray.analyzers.internal_hosts import InternalHostAnalyzer
from jsxray.analyzers.parameters import ParameterAnalyzer
from jsxray.analyzers.secrets import SecretAnalyzer
from jsxray.analyzers.sse import SSEAnalyzer
from jsxray.analyzers.technologies import TechnologyAnalyzer
from jsxray.analyzers.urls import UrlAnalyzer
from jsxray.analyzers.websocket import WebSocketAnalyzer
from jsxray.javascript.parser import JSParser
from jsxray.javascript.reconstruction import StaticReconstructor
from jsxray.models.finding import FindingType
from jsxray.models.source import JavaScriptSource


def create_source_and_reconstructor(code: str):
    parser = JSParser()
    tree, _ = parser.parse(code)
    src = JavaScriptSource(identifier="test.js", original_code=code, ast_root=tree.root_node)
    rec = StaticReconstructor(tree.root_node, code)
    return src, rec


def test_api_analyzer():
    code = """
    const API = "https://api.example.com";
    fetch(API + "/users/" + userId, {
        method: "POST",
        headers: { "Authorization": "Bearer token" }
    });
    axios.get("https://api.example.com/v1/orders");
    """
    src, rec = create_source_and_reconstructor(code)
    analyzer = ApiAnalyzer()
    findings = analyzer.analyze(src, rec)
    assert len(findings) >= 2
    types = [f.type for f in findings]
    assert FindingType.API_ENDPOINT in types
    methods = [f.extra_data.get("method") for f in findings]
    assert "POST" in methods
    assert "GET" in methods


def test_secrets_analyzer():
    code = """
    const awsKey = "AKIAIOSFODNN7EXAMPLE";
    const gcpKey = "AIzaSyD-1234567890abcdefghijklmnopqrst";
    const stripe = "sk_live_51Abcdefghijklmnopqrstuvwx";
    """
    src, rec = create_source_and_reconstructor(code)
    analyzer = SecretAnalyzer()
    findings = analyzer.analyze(src, rec)
    assert len(findings) >= 3
    providers = [f.extra_data.get("provider") for f in findings]
    assert "AWS" in providers
    assert "GCP" in providers
    assert "Stripe" in providers


def test_internal_hosts_analyzer():
    code = """
    const internalUrl = "http://10.0.1.25/admin";
    const local = "http://localhost:8080/metrics";
    """
    src, rec = create_source_and_reconstructor(code)
    analyzer = InternalHostAnalyzer()
    findings = analyzer.analyze(src, rec)
    assert len(findings) >= 2
    types = [f.type for f in findings]
    assert FindingType.INTERNAL_HOST in types
