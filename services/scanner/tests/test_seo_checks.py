from app.scanner.checks.seo import check_seo


def test_missing_title() -> None:
    issues = check_seo(
        page_url="https://example.com/",
        status_code=200,
        content_type="text/html",
        page_title=None,
        html_content="<html><body><h1>Home</h1></body></html>",
    )

    titles = [issue.title for issue in issues]
    assert "Missing page title" in titles


def test_missing_meta_description() -> None:
    issues = check_seo(
        page_url="https://example.com/",
        status_code=200,
        content_type="text/html",
        page_title="A sensible page title",
        html_content="<html><body><h1>Home</h1></body></html>",
    )

    titles = [issue.title for issue in issues]
    assert "Missing meta description" in titles


def test_multiple_h1() -> None:
    issues = check_seo(
        page_url="https://example.com/",
        status_code=200,
        content_type="text/html",
        page_title="A sensible page title",
        html_content="<html><body><h1>One</h1><h1>Two</h1></body></html>",
    )

    titles = [issue.title for issue in issues]
    assert "Multiple H1 headings" in titles


def test_images_missing_alt() -> None:
    issues = check_seo(
        page_url="https://example.com/",
        status_code=200,
        content_type="text/html",
        page_title="A sensible page title",
        html_content=(
            "<html><body><h1>Home</h1>"
            '<img src="/a.png"><img src="/b.png" alt="">'
            "</body></html>"
        ),
    )

    missing_alt_issues = [issue for issue in issues if issue.title == "Images missing alt text"]
    assert len(missing_alt_issues) == 1
    assert missing_alt_issues[0].evidence == "2 images without alt text"


def test_seo_deduplication_behavior_single_issue_per_page() -> None:
    issues = check_seo(
        page_url="https://example.com/",
        status_code=200,
        content_type="text/html",
        page_title="Short",
        html_content=(
            "<html><head><title>Short</title></head>"
            "<body><h1>One</h1><h1>Two</h1><h1>Three</h1></body></html>"
        ),
    )

    multiple_h1_issues = [issue for issue in issues if issue.title == "Multiple H1 headings"]
    assert len(multiple_h1_issues) == 1
