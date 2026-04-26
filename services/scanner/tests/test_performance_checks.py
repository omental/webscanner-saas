from app.scanner.checks.performance import check_performance


def test_slow_page_response() -> None:
    issues = check_performance(
        page_url="https://example.com/",
        status_code=200,
        content_type="text/html",
        response_time_ms=3200,
        headers={"content-type": "text/html"},
    )

    titles = [issue.title for issue in issues]
    assert "Very slow page response" in titles


def test_missing_compression() -> None:
    issues = check_performance(
        page_url="https://example.com/",
        status_code=200,
        content_type="text/html; charset=utf-8",
        response_time_ms=400,
        headers={"content-type": "text/html"},
    )

    titles = [issue.title for issue in issues]
    assert "Missing response compression" in titles


def test_redirect_performance_warning() -> None:
    issues = check_performance(
        page_url="https://example.com/old",
        status_code=301,
        content_type="text/html",
        response_time_ms=200,
        headers={"content-type": "text/html"},
    )

    titles = [issue.title for issue in issues]
    assert "Redirect response detected" in titles


def test_missing_cache_headers_for_static_asset() -> None:
    issues = check_performance(
        page_url="https://example.com/assets/app.css",
        status_code=200,
        content_type="text/css",
        response_time_ms=50,
        headers={"content-type": "text/css", "content-length": "4096"},
    )

    titles = [issue.title for issue in issues]
    assert "Missing asset cache headers" in titles
