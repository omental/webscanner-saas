from app.core.config import Settings
from app.scanner.checks.rce import (
    build_rce_probe_url,
    check_rce_response,
    extract_rce_parameters,
    rce_enabled,
    should_skip_rce_url,
)


def test_rce_disabled_by_default() -> None:
    settings = Settings()

    assert settings.enable_rce_checks is False
    assert rce_enabled(settings.enable_rce_checks) is False


def test_detects_template_evaluation_marker_49() -> None:
    issues = check_rce_response(
        page_url="https://example.com/render?template=test",
        param_name="template",
        probe_family="template_curly",
        response_body="<html>scanner_marker_49</html>",
    )

    assert len(issues) == 1
    assert issues[0].category == "rce_signal"
    assert issues[0].title == "Possible server-side template/code evaluation"
    assert issues[0].severity == "high"
    assert issues[0].confidence == "high"
    assert "scanner_marker_49" in (issues[0].evidence or "")


def test_detects_backend_template_error() -> None:
    issues = check_rce_response(
        page_url="https://example.com/render?template=test",
        param_name="template",
        probe_family="template_curly",
        response_body="jinja2.exceptions.TemplateSyntaxError: unexpected end of template",
    )

    assert len(issues) == 1
    assert issues[0].title == "Possible command execution sink"
    assert issues[0].severity == "medium"
    assert issues[0].confidence == "medium"


def test_no_finding_on_simple_reflection() -> None:
    issues = check_rce_response(
        page_url="https://example.com/render?template=test",
        param_name="template",
        probe_family="template_curly",
        response_body="<p>scanner_marker_{{7*7}}</p>",
    )

    assert issues == []


def test_skips_dangerous_admin_login_upload_urls() -> None:
    assert should_skip_rce_url("https://example.com/admin?cmd=x")
    assert should_skip_rce_url("https://example.com/login?cmd=x")
    assert should_skip_rce_url("https://example.com/upload?path=x")

    params = extract_rce_parameters(
        "https://example.com/admin?cmd=x",
        '<form><input name="cmd"></form>',
        max_params=10,
    )
    assert params == []


def test_max_parameter_limit_respected() -> None:
    params = extract_rce_parameters(
        "https://example.com/search?cmd=a&command=b&exec=c&run=d&host=e",
        None,
        max_params=3,
    )

    assert len(params) == 3


def test_only_risky_parameters_selected_and_probe_preserves_others() -> None:
    params = extract_rce_parameters(
        "https://example.com/search?cmd=a&name=b&domain=c",
        '<form><input name="template"><input name="email"></form>',
        max_params=10,
    )
    url = build_rce_probe_url(
        "https://example.com/search?cmd=a&sort=asc",
        "cmd",
        "scanner_marker_{{7*7}}",
    )

    assert params == ["cmd", "domain", "template"]
    assert "sort=asc" in url
    assert "cmd=scanner_marker_" in url


def test_duplicate_prevention_key_stable() -> None:
    first = check_rce_response(
        page_url="https://example.com/render?template=test",
        param_name="template",
        probe_family="template_curly",
        response_body="scanner_marker_49",
    )[0]
    second = check_rce_response(
        page_url="https://example.com/render?template=test",
        param_name="template",
        probe_family="template_dollar",
        response_body="scanner_marker_49",
    )[0]

    assert first.dedupe_key == second.dedupe_key
