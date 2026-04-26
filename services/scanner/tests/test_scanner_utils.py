from app.scanner.utils import (
    is_same_host,
    normalize_url,
    should_skip_url,
    strip_fragment,
)


def test_normalize_url_normalizes_case_and_fragment() -> None:
    assert (
        normalize_url("HTTPS://Example.COM/path/#section")
        == "https://example.com/path"
    )


def test_normalize_url_trims_trailing_slash_and_preserves_query() -> None:
    assert (
        normalize_url("https://example.com/path/?q=1")
        == "https://example.com/path?q=1"
    )


def test_strip_fragment_removes_hash_only() -> None:
    assert strip_fragment("https://example.com/a?x=1#frag") == "https://example.com/a?x=1"


def test_is_same_host_true_for_same_hostname() -> None:
    assert is_same_host("https://example.com", "https://example.com/about")


def test_is_same_host_false_for_different_subdomain() -> None:
    assert not is_same_host("https://example.com", "https://app.example.com")


def test_should_skip_url_for_non_http_and_destructive_patterns() -> None:
    assert should_skip_url("javascript:void(0)")
    assert should_skip_url("mailto:test@example.com")
    assert should_skip_url("https://example.com/logout")


def test_should_not_skip_regular_http_url() -> None:
    assert not should_skip_url("https://example.com/dashboard")
