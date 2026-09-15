"""Regression and precision test suite for JSXRay 12-point analyzer fixes."""

import pytest
from jsxray.analyzers.authentication import AuthenticationAnalyzer
from jsxray.analyzers.candidates import SecurityCandidateAnalyzer
from jsxray.analyzers.dangerous_js import DangerousJsAnalyzer
from jsxray.analyzers.hosts import HostAnalyzer
from jsxray.analyzers.parameters import ParameterAnalyzer
from jsxray.analyzers.technologies import TechnologyAnalyzer
from jsxray.analyzers.urls import UrlAnalyzer
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


def test_parameter_analyzer_rejects_css_tailwind():
    code = """
    const styles = {
        bg: "bg-red-500",
        text: "text-white",
        border: "border-solid",
        opacity: 0.8,
        hover: "hover:bg-blue-500",
        invert: true,
        underline: false
    };
    function render() {
        return `<div class="${styles.bg} ${styles.text}"></div>`;
    }
    """
    source, reconstructor = create_source_and_reconstructor(code)
    analyzer = ParameterAnalyzer()
    findings = analyzer.analyze(source, reconstructor)

    # None of the CSS classes should be reported as parameters
    param_names = [f.value for f in findings]
    for css_keyword in ["bg", "text", "border", "opacity", "hover", "invert", "underline"]:
        assert css_keyword not in param_names, f"CSS keyword '{css_keyword}' was incorrectly extracted as parameter"


def test_parameter_analyzer_extracts_real_params():
    code = """
    const params = new URLSearchParams();
    params.set('search_query', userInput);
    params.append('filter_tag', 'security');

    axios.get('/api/v1/users', {
        params: {
            page_number: 1,
            page_size: 50
        }
    });

    fetch('/api/v2/items/{itemId}', {
        method: 'POST',
        body: JSON.stringify({ action_name: 'delete' })
    });
    """
    source, reconstructor = create_source_and_reconstructor(code)
    analyzer = ParameterAnalyzer()
    findings = analyzer.analyze(source, reconstructor)

    param_names = {f.value for f in findings}
    assert "search_query" in param_names
    assert "filter_tag" in param_names
    assert "page_number" in param_names
    assert "page_size" in param_names
    assert "itemId" in param_names
    assert "action_name" in param_names

    # Check that metadata and source line are populated
    for f in findings:
        assert f.line is not None and f.line > 0
        assert f.type == FindingType.PARAMETER


def test_idor_candidate_excludes_w3c_namespaces():
    code = """
    const XMLNS_XHTML = "http://www.w3.org/1999/xhtml";
    const XMLNS_SVG = "http://www.w3.org/2000/svg";
    const SVG_XLINK = "http://www.w3.org/1999/xlink";
    """
    source, reconstructor = create_source_and_reconstructor(code)
    url_analyzer = UrlAnalyzer()
    raw_findings = url_analyzer.analyze(source, reconstructor)
    
    cand_analyzer = SecurityCandidateAnalyzer()
    candidates = cand_analyzer.generate_candidates_from_findings(raw_findings)

    idor_findings = [f for f in candidates if "IDOR" in f.extra_data.get("category", "")]
    assert len(idor_findings) == 0, f"W3C namespace URLs were wrongly flagged as IDOR: {idor_findings}"


def test_idor_candidate_detects_real_endpoints():
    code = """
    const userApi = "/api/v1/users/{userId}";
    const orderApi = "/api/v2/orders/:orderId/details";
    """
    source, reconstructor = create_source_and_reconstructor(code)
    url_analyzer = UrlAnalyzer()
    raw_findings = url_analyzer.analyze(source, reconstructor)

    cand_analyzer = SecurityCandidateAnalyzer()
    candidates = cand_analyzer.generate_candidates_from_findings(raw_findings)

    idor_findings = [f for f in candidates if "IDOR" in f.extra_data.get("category", "")]
    assert len(idor_findings) >= 2


def test_host_analyzer_classifies_standard_and_external_hosts():
    code = """
    const w3 = "http://www.w3.org/1999/xhtml";
    const svelte = "https://svelte.dev/docs";
    const yt = "https://youtube.com/watch?v=123";
    const apiHost = "https://api.myapp.production.com/v1";
    """
    source, reconstructor = create_source_and_reconstructor(code)
    analyzer = HostAnalyzer()
    findings = analyzer.analyze(source, reconstructor)

    hosts_by_val = {f.value: f for f in findings}
    
    # www.w3.org and svelte.dev / youtube.com should NOT be FindingType.API_HOST
    if "www.w3.org" in hosts_by_val:
        assert hosts_by_val["www.w3.org"].type == FindingType.EXTERNAL_URL
    if "svelte.dev" in hosts_by_val:
        assert hosts_by_val["svelte.dev"].type == FindingType.EXTERNAL_URL

    # api.myapp.production.com MUST be FindingType.API_HOST
    assert "api.myapp.production.com" in hosts_by_val
    assert hosts_by_val["api.myapp.production.com"].type == FindingType.API_HOST


def test_url_analyzer_separates_static_assets():
    code = """
    const appRoute = "/dashboard/settings/profile";
    const apiRoute = "/api/v2/auth/login";
    const scriptAsset = "/cdn/assets/bundle-c7p85l1r.js";
    const styleAsset = "/styles/theme.min.css";
    const w3Link = "http://www.w3.org/1999/xhtml";
    """
    source, reconstructor = create_source_and_reconstructor(code)
    analyzer = UrlAnalyzer()
    findings = analyzer.analyze(source, reconstructor)

    by_type = {}
    for f in findings:
        by_type.setdefault(f.type, []).append(f.value)

    # Routes should be in URL_ROUTE
    assert "/dashboard/settings/profile" in by_type.get(FindingType.URL_ROUTE, [])
    assert "/api/v2/auth/login" in by_type.get(FindingType.URL_ROUTE, [])

    # Static assets should be in STATIC_RESOURCE
    static_list = by_type.get(FindingType.STATIC_RESOURCE, [])
    assert "/cdn/assets/bundle-c7p85l1r.js" in static_list
    assert "/styles/theme.min.css" in static_list

    # W3C should be EXTERNAL_URL
    assert "http://www.w3.org/1999/xhtml" in by_type.get(FindingType.EXTERNAL_URL, [])


def test_dangerous_js_classifies_sinks():
    code = """
    // Static navigation
    window.location.href = "/dashboard";

    // Dynamic sink
    document.getElementById("target").innerHTML = userPayload;

    // Evaluated expression
    eval(dynamicScript);
    """
    source, reconstructor = create_source_and_reconstructor(code)
    analyzer = DangerousJsAnalyzer()
    findings = analyzer.analyze(source, reconstructor)

    sinks = {f.extra_data.get("sink"): f for f in findings}
    assert "innerHTML" in sinks
    assert "eval" in sinks
    assert "location.href" in sinks

    # location.href with static "/dashboard" should have note about static navigation
    loc_finding = sinks["location.href"]
    assert "Static" in loc_finding.extra_data.get("exploitability", "")


def test_authentication_analyzer_ignores_log_messages():
    code = """
    console.log("No token found in localStorage for user session");
    console.error("JWT token expired, logging out");
    const authHeader = "Authorization: Bearer " + token;
    """
    source, reconstructor = create_source_and_reconstructor(code)
    analyzer = AuthenticationAnalyzer()
    findings = analyzer.analyze(source, reconstructor)

    for f in findings:
        assert "No token found in localStorage" not in f.value
        assert "JWT token expired" not in f.value


def test_technology_analyzer_detects_svelte_vite_react():
    code_svelte = """
    import { create_ssr_component } from "svelte/internal";
    export default create_ssr_component(...);
    """
    src_sv, rec_sv = create_source_and_reconstructor(code_svelte)
    techs_svelte = [f.normalized_value for f in TechnologyAnalyzer().analyze(src_sv, rec_sv)]
    assert "Svelte" in techs_svelte

    code_vite = """
    if (import.meta.hot) {
        import.meta.hot.accept();
    }
    """
    src_vi, rec_vi = create_source_and_reconstructor(code_vite)
    techs_vite = [f.normalized_value for f in TechnologyAnalyzer().analyze(src_vi, rec_vi)]
    assert "Vite" in techs_vite

    code_graphql = """
    const query = gql`
      query GetUser {
        user { id name }
      }
    `;
    """
    src_gq, rec_gq = create_source_and_reconstructor(code_graphql)
    techs_gql = [f.normalized_value for f in TechnologyAnalyzer().analyze(src_gq, rec_gq)]
    assert "GraphQL" in techs_gql
