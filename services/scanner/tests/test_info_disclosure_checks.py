from app.scanner.checks.info_disclosure import (
    check_banner_exposure,
    check_debug_exposure,
    check_directory_listing,
    classify_sensitive_file_exposure,
)


def test_banner_exposure_finding_logic() -> None:
    issues = check_banner_exposure(
        "https://example.com",
        {"server": "nginx/1.25.0"},
    )

    assert len(issues) == 1
    assert issues[0].title == "Exposed server banner"


def test_x_powered_by_exposure_logic() -> None:
    issues = check_banner_exposure(
        "https://example.com",
        {"x-powered-by": "Express"},
    )

    assert len(issues) == 1
    assert issues[0].title == "Exposed X-Powered-By header"


def test_directory_listing_pattern_detection() -> None:
    issues = check_directory_listing(
        "https://example.com/files/",
        "Index of /files",
        None,
    )

    assert len(issues) == 1
    assert issues[0].title == "Possible directory listing exposure"


def test_debug_keyword_detection() -> None:
    issues = check_debug_exposure(
        "https://example.com/error",
        None,
        "Traceback (most recent call last): ValueError",
    )

    assert len(issues) == 1
    assert issues[0].category == "debug_exposure"


def test_git_head_exposure_classification() -> None:
    issues = classify_sensitive_file_exposure(
        "/.git/HEAD",
        200,
        "ref: refs/heads/main\n",
        "text/plain",
    )

    assert len(issues) == 1
    assert issues[0].title == "Exposed .git metadata"


def test_env_exposure_classification() -> None:
    issues = classify_sensitive_file_exposure(
        "/.env",
        200,
        "DATABASE_URL=postgresql://db\nAPP_KEY=secret\n",
        "text/plain",
    )

    assert len(issues) == 1
    assert issues[0].title == "Exposed .env file"
