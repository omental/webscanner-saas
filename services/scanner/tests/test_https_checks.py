from app.scanner.checks.https import check_mixed_content, classify_transport


def test_basic_https_classification_no_issue_for_https() -> None:
    assert classify_transport("https://example.com", "https://example.com") == []


def test_redirect_to_https_classification_no_issue() -> None:
    assert classify_transport("http://example.com", "https://example.com") == []


def test_http_only_site_creates_high_severity_issue() -> None:
    issues = classify_transport(
        "http://example.com",
        "http://example.com",
        https_available=False,
    )

    assert len(issues) == 1
    assert issues[0].category == "insecure_transport"
    assert issues[0].title == "No HTTPS available"
    assert issues[0].severity == "high"


def test_https_site_without_http_redirect_creates_medium_issue() -> None:
    issues = classify_transport(
        "http://example.com",
        "http://example.com",
        https_available=True,
    )

    assert len(issues) == 1
    assert issues[0].title == "HTTP does not redirect to HTTPS"
    assert issues[0].severity == "medium"
    assert "url=http://example.com" in (issues[0].evidence or "")


def test_https_page_with_http_asset_creates_mixed_content_issue() -> None:
    issues = check_mixed_content(
        "https://example.com",
        '<html><script src="http://cdn.example.com/app.js"></script></html>',
    )

    assert len(issues) == 1
    assert issues[0].title == "Mixed content asset"
    assert "url=https://example.com" in (issues[0].evidence or "")
    assert "sample_asset=http://cdn.example.com/app.js" in (issues[0].evidence or "")


def test_proper_https_site_has_no_transport_or_mixed_content_findings() -> None:
    assert classify_transport(
        "http://example.com",
        "https://example.com",
        https_available=True,
    ) == []
    assert check_mixed_content(
        "https://example.com",
        '<html><script src="https://cdn.example.com/app.js"></script></html>',
    ) == []
