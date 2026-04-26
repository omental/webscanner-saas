from app.core.config import Settings
from app.scanner.checks.subdomains import discover_subdomains_from_page


def test_extracts_subdomain_from_link() -> None:
    issues = discover_subdomains_from_page(
        "https://example.com",
        "https://example.com",
        '<a href="https://blog.example.com/post">Blog</a>',
        {},
    )

    assert len(issues) == 1
    assert issues[0].category == "subdomain_discovery"
    assert issues[0].title == "Discovered related subdomain"
    assert issues[0].severity == "informational"
    assert issues[0].confidence == "high"
    assert "subdomain=blog.example.com" in (issues[0].evidence or "")
    assert "source_type=link" in (issues[0].evidence or "")


def test_extracts_subdomain_from_asset_url() -> None:
    issues = discover_subdomains_from_page(
        "https://example.com",
        "https://example.com",
        '<script src="https://cdn.example.com/app.js"></script>',
        {},
    )

    assert len(issues) == 1
    assert issues[0].confidence == "medium"
    assert "subdomain=cdn.example.com" in (issues[0].evidence or "")
    assert "source_type=link" in (issues[0].evidence or "")


def test_extracts_subdomain_from_location_header() -> None:
    issues = discover_subdomains_from_page(
        "https://example.com",
        "https://example.com/login",
        None,
        {"Location": "https://auth.example.com/start"},
    )

    assert len(issues) == 1
    assert issues[0].confidence == "high"
    assert "subdomain=auth.example.com" in (issues[0].evidence or "")
    assert "source_type=header" in (issues[0].evidence or "")


def test_extracts_subdomain_from_csp() -> None:
    issues = discover_subdomains_from_page(
        "https://example.com",
        "https://example.com",
        None,
        {
            "Content-Security-Policy": (
                "default-src 'self'; img-src https://images.example.com"
            )
        },
    )

    assert len(issues) == 1
    assert "subdomain=images.example.com" in (issues[0].evidence or "")
    assert "source_type=csp" in (issues[0].evidence or "")


def test_excludes_third_party_domains() -> None:
    issues = discover_subdomains_from_page(
        "https://example.com",
        "https://example.com",
        (
            '<a href="https://google.com/search">Search</a>'
            '<script src="https://cdn.facebook.com/sdk.js"></script>'
        ),
        {"Location": "https://accounts.google.com/login"},
    )

    assert issues == []


def test_dedupes_repeated_subdomain() -> None:
    issues = discover_subdomains_from_page(
        "https://example.com",
        "https://example.com",
        (
            '<a href="https://blog.example.com/a">A</a>'
            '<a href="https://blog.example.com/b">B</a>'
        ),
        {"Link": '<https://blog.example.com/feed>; rel="alternate"'},
    )

    assert len(issues) == 1
    assert issues[0].dedupe_key == "subdomain:blog.example.com"


def test_respects_max_results() -> None:
    html = "".join(
        f'<a href="https://sub{index}.example.com/page">{index}</a>'
        for index in range(5)
    )

    issues = discover_subdomains_from_page(
        "https://example.com",
        "https://example.com",
        html,
        {},
        max_results=3,
    )

    assert len(issues) == 3


def test_subdomain_discovery_disabled_by_default() -> None:
    assert Settings(_env_file=None).enable_subdomain_discovery is False
