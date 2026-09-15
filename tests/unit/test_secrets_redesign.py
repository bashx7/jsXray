"""Unit tests for the redesigned JSXRay Secret Detection Engine."""

import pytest
from jsxray.analyzers.secrets import SecretAnalyzer
from jsxray.javascript.parser import JSParser
from jsxray.javascript.reconstruction import StaticReconstructor
from jsxray.models.finding import Confidence, FindingStatus, FindingType
from jsxray.models.source import JavaScriptSource
from jsxray.secrets.classifier import SecretClassifier
from jsxray.secrets.confidence import ConfidenceScorer
from jsxray.secrets.definitions import get_all_detectors
from jsxray.secrets.engine import SecretDetectionEngine, mask_secret


def create_source(code: str):
    parser = JSParser()
    tree, _ = parser.parse(code)
    src = JavaScriptSource(identifier="app.js", original_code=code, ast_root=tree.root_node)
    rec = StaticReconstructor(tree.root_node, code)
    return src, rec


def test_detector_count_at_least_500():
    """Verify that the structured detector catalog contains at least 500 rules."""
    detectors = get_all_detectors()
    assert len(detectors) >= 500, f"Expected >= 500 detectors, found {len(detectors)}"


def test_false_positive_rejection_user_examples():
    """Verify that routes, bundle assets, and hashes are NOT detected as secrets."""
    fps = [
        "routes/codex.cloud.settings.access-tokens",
        "/cdn/assets/codex.cloud.settings.access-tokens-huqqaia3.js",
        "routes/admin.access-tokens",
        "/cdn/assets/admin.access-tokens-c7p85l1r.js",
        "/static/chunks/app-tokens-12345678.js",
        "123e4567-e89b-12d3-a456-426614174000",
        "flex flex-col items-center justify-between p-4",
        "settings.access-tokens.tab.title",
        "your_api_key_here",
    ]

    for fp in fps:
        is_fp, reason = SecretClassifier.is_false_positive(fp)
        assert is_fp, f"Expected '{fp}' to be classified as false positive, but wasn't! Reason: {reason}"


def test_js_code_false_positive_suppression():
    """Test full JS code containing route definitions and asset imports produces zero secret findings."""
    code = """
    import AccessTokenModule from "/cdn/assets/codex.cloud.settings.access-tokens-huqqaia3.js";
    import AdminTokens from "/cdn/assets/admin.access-tokens-c7p85l1r.js";

    const routes = {
        settings: "routes/codex.cloud.settings.access-tokens",
        admin: "routes/admin.access-tokens",
        id: "c4a8a09f-6827-4976-96b6-a36c53579b9a"
    };
    """
    src, rec = create_source(code)
    analyzer = SecretAnalyzer()
    findings = analyzer.analyze(src, rec)
    assert len(findings) == 0, f"Expected 0 secrets, got {len(findings)}: {[f.value for f in findings]}"


def test_major_vendor_detection():
    """Test positive detection of known cloud, AI, payment, and SaaS providers."""
    code = """
    // AWS Access Key
    const aws = "AKIAIOSFODNN7EXAMPLE";
    // OpenAI API Key
    const openai = "sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcDeFgHiJkLmNoP";
    // Anthropic API Key
    const anthropic = "sk-ant-api03-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklm-AA";
    // Stripe Secret Key
    const stripe = "sk_live_51Abcdefghijklmnopqrstuvwx";
    // SendGrid API Key
    const sendgrid = "SG.abcdefghijklmnopqrstuv.1234567890abcdefghijklmnopqrstuvwxyz12345";
    // GitHub PAT
    const github = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
    // Slack Bot Token
    const slack = "xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx";
    // HuggingFace Token
    const hf = "hf_abcdefghijklmnopqrstuvwxyz12345678";
    // Groq API Key
    const groq = "gsk_abcdefghijklmnopqrstuvwxyz1234567890123456789012";
    """
    src, rec = create_source(code)
    analyzer = SecretAnalyzer()
    findings = analyzer.analyze(src, rec)

    providers = {f.extra_data.get("provider") for f in findings}
    assert "AWS" in providers
    assert "OpenAI" in providers
    assert "Anthropic" in providers
    assert "Stripe" in providers
    assert "SendGrid" in providers
    assert "GitHub" in providers
    assert "Slack" in providers
    assert ("Hugging Face" in providers or "HuggingFace" in providers)
    assert "Groq" in providers


def test_contextual_generic_secret_detection():
    """Test generic credential variable assignment and header detection."""
    code = """
    const apiKey = "f8a912bc47de89201fa8394bc87123de";
    const client_secret = "99e8271ab34cd65ef01928374650a98b";
    fetch("https://api.example.com", {
        headers: {
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature123456"
        }
    });
    """
    src, rec = create_source(code)
    analyzer = SecretAnalyzer()
    findings = analyzer.analyze(src, rec)

    assert len(findings) >= 2
    types = [f.extra_data.get("secret_name") for f in findings]
    assert any("Generic" in t or "Bearer" in t for t in types)


def test_confidence_and_masking():
    """Test confidence scoring and secret masking."""
    val = "sk_live_51Abcdefghijklmnopqrstuvwx"
    masked = mask_secret(val)
    assert masked.startswith("sk_l")
    assert masked.endswith("uvwx")
    assert "*" in masked

    score, num_score, reason = ConfidenceScorer.evaluate(val, is_generic=False)
    assert score in ("High", "Medium")
    assert num_score >= 50
