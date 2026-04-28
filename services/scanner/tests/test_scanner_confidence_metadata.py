import asyncio
from types import SimpleNamespace

from app.scanner.checks.exposure_paths import classify_exposure_path
from app.scanner.checks.headers import check_security_headers
from app.scanner.checks.rce import check_rce_response
from app.scanner.checks.reflected_xss import check_reflected_xss
from app.scanner.checks.sqli_advanced import ResponseSnapshot, check_timing_sqli
from app.scanner.checks.sqli_light import check_sqli_light
from app.scanner.checks.ssrf import check_ssrf_response
from app.services.finding_service import create_findings_if_missing


def test_missing_header_has_low_or_medium_metadata() -> None:
    issue = check_security_headers("https://example.com", {})[0]

    assert issue.confidence_level in {"low", "medium"}
    assert issue.confidence_score is not None
    assert issue.evidence_type in {"weak_signal", "multiple_signals"}
    assert issue.verification_steps


def test_sensitive_file_exposure_can_be_confirmed() -> None:
    issue = classify_exposure_path(
        "/.env",
        "https://example.com/.env",
        200,
        "DATABASE_URL=postgres://db",
        "text/plain",
    )[0]

    assert issue.confidence_level == "confirmed"
    assert issue.confidence_score >= 90
    assert issue.response_snippet


def test_reflected_xss_metadata_tracks_context() -> None:
    marker = "SCANNER_XSS_MARKER_test"
    text_issue = check_reflected_xss(
        "https://example.com/search",
        "q",
        marker,
        f"<p>{marker}</p>",
    )[0]
    script_issue = check_reflected_xss(
        "https://example.com/search",
        "q",
        marker,
        f"<script>window.q='{marker}'</script>",
    )[0]

    assert text_issue.confidence_level == "medium"
    assert script_issue.confidence_level == "high"
    assert script_issue.affected_parameter == "q"


def test_sqli_metadata_distinguishes_error_and_timing_confirmation() -> None:
    error_issue = check_sqli_light(
        "https://example.com/item",
        "id",
        "'",
        "Warning: MySQL error. You have an error in your SQL syntax",
        baseline_body="normal item page",
    )[0]
    timing_issue = check_timing_sqli(
        "https://example.com/item?id=1",
        "id",
        ResponseSnapshot(200, "ok", 100),
        ResponseSnapshot(200, "ok", 3300),
        repeat_response=ResponseSnapshot(200, "ok", 3400),
    )[0]

    assert error_issue.confidence_level == "medium"
    assert error_issue.affected_parameter == "id"
    assert error_issue.request_url == "https://example.com/item"
    assert error_issue.http_method == "GET"
    assert error_issue.tested_parameter == "id"
    assert error_issue.payload == "'"
    assert error_issue.attack_response_size is not None
    assert timing_issue.confidence_level == "confirmed"
    assert timing_issue.confidence_score >= 90
    assert timing_issue.baseline_response_time_ms == 100
    assert timing_issue.attack_response_time_ms == 3300
    assert timing_issue.response_diff_summary == "timing_delta_ms=3200; repeat_delta_ms=3300"


def test_ssrf_and_rce_metadata_follow_signal_strength() -> None:
    ssrf_issue = check_ssrf_response(
        page_url="https://example.com/proxy?url=https://old.example",
        param_name="url",
        callback_url="https://canary.example/abc",
        response_body=None,
        callback_confirmed=True,
    )[0]
    rce_issue = check_rce_response(
        page_url="https://example.com/render?template=test",
        param_name="template",
        probe_family="template_curly",
        response_body="<html>scanner_marker_49</html>",
    )[0]

    assert ssrf_issue.confidence_level == "confirmed"
    assert ssrf_issue.payload_used == "https://canary.example/abc"
    assert ssrf_issue.payload == "https://canary.example/abc"
    assert rce_issue.confidence_level == "high"
    assert rce_issue.affected_parameter == "template"
    assert rce_issue.request_url == "https://example.com/render?template=test"


def test_finding_service_persists_issue_metadata() -> None:
    added = []

    class Result:
        def scalar_one_or_none(self):
            return None

    async def execute(_query):
        return Result()

    async def commit():
        return None

    issue = check_reflected_xss(
        "https://example.com/search",
        "q",
        "SCANNER_XSS_MARKER_test",
        "<p>SCANNER_XSS_MARKER_test</p>",
    )[0]
    session = SimpleNamespace(add=added.append, commit=commit, execute=execute)

    asyncio.run(
        create_findings_if_missing(
            session,
            scan_id=1,
            scan_page_id=2,
            issues=[issue],
        )
    )

    assert added[0].confidence_level == "medium"
    assert added[0].confidence_score is not None
    assert added[0].affected_parameter == "q"
    assert added[0].request_url == "https://example.com/search"
    assert added[0].tested_parameter == "q"
    assert added[0].payload == "SCANNER_XSS_MARKER_test"
