from app.scanner.checks.headers import check_security_headers


def test_missing_header_detection() -> None:
    issues = check_security_headers("https://example.com", {})

    titles = {issue.title for issue in issues}
    assert "Missing Content-Security-Policy" in titles
    assert "Missing X-Frame-Options" in titles
    assert "Missing X-Content-Type-Options" in titles
    assert "Missing Referrer-Policy" in titles
    assert "Missing Strict-Transport-Security" in titles


def test_no_hsts_finding_for_plain_http_page() -> None:
    issues = check_security_headers("http://example.com", {})

    titles = {issue.title for issue in issues}
    assert "Missing Strict-Transport-Security" not in titles


def test_finding_generation_logic_uses_expected_category() -> None:
    issues = check_security_headers(
        "https://example.com",
        {"x-frame-options": "DENY", "x-content-type-options": "nosniff"},
    )

    assert any(issue.category == "missing_security_header" for issue in issues)
