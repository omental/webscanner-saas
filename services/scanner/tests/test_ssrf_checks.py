from app.core.config import Settings
from app.scanner.checks.ssrf import (
    build_ssrf_probe_url,
    check_ssrf_response,
    extract_ssrf_parameters,
    is_safe_ssrf_probe_url,
    ssrf_enabled,
)


def test_ssrf_disabled_by_default() -> None:
    settings = Settings()

    assert settings.enable_ssrf_checks is False
    assert ssrf_enabled(settings.enable_ssrf_checks) is False


def test_only_url_like_params_selected() -> None:
    params = extract_ssrf_parameters(
        "https://example.com/fetch?url=https://a.example&name=b&avatar=c&x=y",
        '<form><input name="endpoint"><input name="username"></form>',
        max_params=10,
    )

    assert params == ["avatar", "endpoint", "url"]


def test_blocks_internal_ip_and_dangerous_payloads() -> None:
    blocked = [
        "http://127.0.0.1/callback",
        "http://localhost/callback",
        "http://169.254.169.254/latest/meta-data",
        "http://10.0.0.1/callback",
        "http://172.16.0.1/callback",
        "http://192.168.1.10/callback",
        "file:///etc/passwd",
        "gopher://example.com",
    ]

    assert all(not is_safe_ssrf_probe_url(url) for url in blocked)
    assert is_safe_ssrf_probe_url("https://canary.example/callback")
    assert (
        build_ssrf_probe_url(
            "https://example.com/proxy?url=https://old.example",
            "url",
            "http://127.0.0.1/callback",
        )
        is None
    )


def test_medium_finding_on_strong_backend_fetch_error() -> None:
    issues = check_ssrf_response(
        page_url="https://example.com/proxy?url=https://old.example",
        param_name="url",
        callback_url="https://canary.example/abc",
        response_body="Proxy error: failed to fetch remote URL",
    )

    assert len(issues) == 1
    assert issues[0].category == "ssrf"
    assert issues[0].severity == "medium"
    assert issues[0].confidence == "medium"
    assert "callback_domain=canary.example" in (issues[0].evidence or "")
    assert "127.0.0.1" not in (issues[0].evidence or "")


def test_high_finding_on_callback_confirmation() -> None:
    issues = check_ssrf_response(
        page_url="https://example.com/proxy?url=https://old.example",
        param_name="url",
        callback_url="https://canary.example/abc",
        response_body=None,
        callback_confirmed=True,
    )

    assert len(issues) == 1
    assert issues[0].severity == "high"
    assert issues[0].confidence == "high"


def test_no_finding_on_simple_reflection() -> None:
    issues = check_ssrf_response(
        page_url="https://example.com/proxy?url=https://old.example",
        param_name="url",
        callback_url="https://canary.example/abc",
        response_body="<p>https://canary.example/abc</p>",
    )

    assert issues == []


def test_limit_respected() -> None:
    params = extract_ssrf_parameters(
        "https://example.com/?url=a&uri=b&link=c&target=d&endpoint=e",
        None,
        max_params=3,
    )

    assert len(params) == 3


def test_duplicate_prevention_key_stable() -> None:
    first = check_ssrf_response(
        page_url="https://example.com/proxy?url=https://old.example",
        param_name="url",
        callback_url="https://canary.example/one",
        response_body="failed to fetch remote URL",
    )[0]
    second = check_ssrf_response(
        page_url="https://example.com/proxy?url=https://old.example",
        param_name="url",
        callback_url="https://canary.example/two",
        response_body="could not fetch remote URL",
    )[0]

    assert first.dedupe_key == second.dedupe_key
