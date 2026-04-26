from app.scanner.checks.waf_detection import (
    WafProbeSnapshot,
    build_waf_probe_url,
    detect_waf_behavior,
    detect_waf_from_headers,
)


def test_detects_cloudflare_from_cf_ray() -> None:
    issues = detect_waf_from_headers(
        "https://example.com",
        {"cf-ray": "8f123abc-DAC"},
    )

    assert len(issues) == 1
    assert issues[0].title == "WAF/CDN detected"
    assert issues[0].category == "waf_detection"
    assert issues[0].severity == "informational"
    assert issues[0].confidence == "high"
    assert "vendor=Cloudflare" in (issues[0].evidence or "")
    assert "matched=cf-ray" in (issues[0].evidence or "")


def test_detects_sucuri_from_x_sucuri_id() -> None:
    issues = detect_waf_from_headers(
        "https://example.com",
        {"x-sucuri-id": "11012"},
    )

    assert len(issues) == 1
    assert "vendor=Sucuri" in (issues[0].evidence or "")
    assert "matched=x-sucuri-id" in (issues[0].evidence or "")


def test_detects_cloudfront_from_x_amz_cf_id() -> None:
    issues = detect_waf_from_headers(
        "https://example.com",
        {"x-amz-cf-id": "abc123"},
    )

    assert len(issues) == 1
    assert "vendor=AWS CloudFront" in (issues[0].evidence or "")
    assert "matched=x-amz-cf-id" in (issues[0].evidence or "")


def test_detects_wordfence_cookie_or_header() -> None:
    cookie_issues = detect_waf_from_headers(
        "https://example.com",
        {"set-cookie": "wfwaf-authcookie-123=abc; Path=/; HttpOnly"},
    )
    header_issues = detect_waf_from_headers(
        "https://example.com",
        {"x-waf": "Wordfence"},
    )

    assert "vendor=Wordfence" in (cookie_issues[0].evidence or "")
    assert "matched=set-cookie" in (cookie_issues[0].evidence or "")
    assert "vendor=Wordfence" in (header_issues[0].evidence or "")
    assert "matched=x-waf" in (header_issues[0].evidence or "")


def test_behavior_signal_on_403_response() -> None:
    baseline = WafProbeSnapshot(
        url="https://example.com",
        status_code=200,
        headers={},
        body="<title>Home</title>",
        page_title="Home",
    )
    probe = WafProbeSnapshot(
        url=build_waf_probe_url("https://example.com"),
        status_code=403,
        headers={},
        body="<title>Access denied</title>",
    )

    issues = detect_waf_behavior(baseline, probe)

    assert len(issues) == 1
    assert issues[0].title == "Possible WAF challenge or block page detected"
    assert issues[0].category == "waf_detection"
    assert issues[0].severity == "informational"
    assert issues[0].confidence == "medium"
    assert "status_code=403" in (issues[0].evidence or "")
    assert "snippet=Access denied" in (issues[0].evidence or "")


def test_no_finding_on_normal_response() -> None:
    baseline = WafProbeSnapshot(
        url="https://example.com",
        status_code=200,
        headers={},
        body="<title>Home</title>",
        page_title="Home",
    )
    probe = WafProbeSnapshot(
        url=build_waf_probe_url("https://example.com"),
        status_code=200,
        headers={},
        body="<title>Home</title>",
        page_title="Home",
    )

    assert detect_waf_from_headers("https://example.com", {}) == []
    assert detect_waf_behavior(baseline, probe) == []


def test_dedupe_vendor_finding() -> None:
    issues = detect_waf_from_headers(
        "https://example.com",
        {
            "cf-ray": "8f123abc-DAC",
            "cf-cache-status": "DYNAMIC",
            "server": "cloudflare",
        },
    )

    assert len(issues) == 1
    assert issues[0].dedupe_key == "waf:vendor:cloudflare"
