"""Tests for Subdomain & API Host scoping, domain inference, and copy features."""

import pytest
from jsxray.analyzers.hosts import HostAnalyzer
from jsxray.cli import create_parser
from jsxray.engine import infer_domain_from_urls
from jsxray.javascript.parser import JSParser
from jsxray.javascript.reconstruction import StaticReconstructor
from jsxray.models.finding import FindingType
from jsxray.models.source import JavaScriptSource


def create_source_and_reconstructor(code: str, name: str = "test.js"):
    parser = JSParser()
    tree, _ = parser.parse(code)
    src = JavaScriptSource(identifier=name, original_code=code, ast_root=tree.root_node if tree else None)
    rec = StaticReconstructor(tree.root_node if tree else None, code)
    return src, rec


def test_host_analyzer_target_domain_scoping():
    code = """
    const primaryApi = "https://api.target.com/v1/auth";
    const adminPanel = "https://admin.staging.target.com/dashboard";
    const nakedHost = "auth.target.com";
    const thirdParty = "https://api.stripe.com/v1/charges";
    const external = "https://svelte.dev/tutorial";
    """
    src, rec = create_source_and_reconstructor(code)
    analyzer = HostAnalyzer(target_domain="target.com")
    findings = analyzer.analyze(src, rec)

    by_val = {f.value: f for f in findings}

    # Verify In-Scope Subdomains
    assert "api.target.com" in by_val
    assert by_val["api.target.com"].type == FindingType.API_HOST
    assert by_val["api.target.com"].extra_data.get("is_in_scope") is True
    assert "in-scope" in by_val["api.target.com"].tags

    assert "admin.staging.target.com" in by_val
    assert by_val["admin.staging.target.com"].type == FindingType.API_HOST
    assert by_val["admin.staging.target.com"].extra_data.get("is_in_scope") is True

    assert "auth.target.com" in by_val
    assert by_val["auth.target.com"].extra_data.get("is_in_scope") is True

    # Verify Third-Party API
    assert "api.stripe.com" in by_val
    assert by_val["api.stripe.com"].type == FindingType.API_HOST
    assert by_val["api.stripe.com"].extra_data.get("is_in_scope") is False

    # Verify External Reference
    if "svelte.dev" in by_val:
        assert by_val["svelte.dev"].type == FindingType.EXTERNAL_URL


def test_infer_domain_from_urls():
    urls = [
        "https://app.example.com/assets/main.js",
        "https://admin.example.com/bundle.js",
        "https://example.com/runtime.js",
        "https://cdn.jsdelivr.net/npm/vue.js",
    ]
    inferred = infer_domain_from_urls(urls)
    assert inferred == "example.com"


def test_cli_domain_argument():
    parser = create_parser()
    args = parser.parse_args(["-jf", "src", "-d", "example.com"])
    assert args.domain == "example.com"

    args_no_domain = parser.parse_args(["-jf", "src"])
    assert args_no_domain.domain is None
