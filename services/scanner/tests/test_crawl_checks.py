from types import SimpleNamespace

from app.scanner.checks.crawl import (
    check_crawl_page,
    check_redirect_chains,
    summarize_crawl_issues,
)


def page(
    url: str,
    status_code: int,
    *,
    location: str | None = None,
    discovered_from: str | None = None,
) -> SimpleNamespace:
    headers = {"location": location} if location else {}
    return SimpleNamespace(
        url=url,
        status_code=status_code,
        response_headers=headers,
        discovered_from=discovered_from,
    )


def test_page_returning_404_creates_low_severity_finding() -> None:
    issues = check_crawl_page(
        page(
            "https://example.com/missing",
            404,
            discovered_from="https://example.com",
        )
    )

    assert len(issues) == 1
    assert issues[0].category == "crawl_issue"
    assert issues[0].title == "Page returns 404"
    assert issues[0].severity == "low"
    assert "url=https://example.com/missing" in (issues[0].evidence or "")


def test_redirect_page_creates_info_finding() -> None:
    issues = check_crawl_page(
        page("https://example.com/old", 301, location="/new")
    )

    assert len(issues) == 1
    assert issues[0].title == "Redirect page"
    assert issues[0].severity == "info"
    assert "location=https://example.com/new" in (issues[0].evidence or "")


def test_normal_page_has_no_crawl_issue() -> None:
    assert check_crawl_page(page("https://example.com", 200)) == []


def test_redirect_chain_depth_greater_than_one_creates_site_wide_finding() -> None:
    issues = check_redirect_chains(
        [
            page("https://example.com/a", 301, location="/b"),
            page("https://example.com/b", 302, location="/c"),
            page("https://example.com/c", 200),
        ]
    )

    assert len(issues) == 1
    assert issues[0].title == "Redirect chain detected"
    assert "https://example.com/a -> https://example.com/b -> https://example.com/c" in (
        issues[0].evidence or ""
    )


def test_crawl_summary_counts_dead_internal_links_and_redirects() -> None:
    issues = summarize_crawl_issues(
        [
            page(
                "https://example.com/missing",
                404,
                discovered_from="https://example.com",
            ),
            page("https://example.com/old", 301, location="/new"),
            page("https://example.com/new", 200),
        ]
    )

    assert len(issues) == 1
    assert issues[0].title == "Crawl issue summary"
    assert "404_pages=1" in (issues[0].evidence or "")
    assert "redirects=1" in (issues[0].evidence or "")
    assert "dead_internal_links=1" in (issues[0].evidence or "")
