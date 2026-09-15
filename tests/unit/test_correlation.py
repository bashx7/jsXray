from jsxray.correlation.correlate import CorrelationEngine
from jsxray.correlation.deduplicate import deduplicate_findings
from jsxray.models.finding import Confidence, Finding, FindingStatus, FindingType
from jsxray.models.scan import ScanMetadata, ScanResult
from jsxray.reporting.html import HtmlReporter


def test_deduplication_and_occurrence_aggregation():
    f1 = Finding(
        type=FindingType.API_ENDPOINT,
        value="GET /api/users/100",
        normalized_value="/api/users/100",
        source_file="app.js",
        line=10,
    )
    f2 = Finding(
        type=FindingType.API_ENDPOINT,
        value="GET /api/users/101",
        normalized_value="/api/users/101",
        source_file="dashboard.js",
        line=45,
    )
    deduped = deduplicate_findings([f1, f2])
    # Both normalize to /api/users/{id}
    assert len(deduped) == 1
    assert deduped[0].normalized_value == "/api/users/{id}"
    assert len(deduped[0].occurrences) == 2


def test_html_reporter_generation():
    meta = ScanMetadata(
        scan_id="test-123",
        target_input="test.js",
        input_mode="Local JS File",
    )
    res = ScanResult(metadata=meta)
    res.findings.append(
        Finding(
            type=FindingType.API_ENDPOINT,
            value="GET https://api.example.com/users",
            normalized_value="https://api.example.com/users",
            confidence=Confidence.HIGH,
            status=FindingStatus.DETECTED,
            source_file="test.js",
            line=12,
        )
    )
    reporter = HtmlReporter(res)
    html_output = reporter.generate()
    assert "<!DOCTYPE html>" in html_output
    assert "JSXRay Report" in html_output
    assert "https://api.example.com/users" in html_output
