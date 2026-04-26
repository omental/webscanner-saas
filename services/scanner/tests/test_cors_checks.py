from app.scanner.checks.cors import check_cors_headers


def test_wildcard_acao_creates_medium_finding_without_credentials() -> None:
    issues = check_cors_headers(
        "https://example.com/api",
        "https://evil.example",
        {"access-control-allow-origin": "*"},
    )

    assert len(issues) == 1
    assert issues[0].category == "cors_misconfiguration"
    assert issues[0].title == "Wildcard CORS origin"
    assert issues[0].severity == "medium"
    assert "url=https://example.com/api" in (issues[0].evidence or "")


def test_reflected_origin_creates_high_finding() -> None:
    issues = check_cors_headers(
        "https://example.com/api",
        "https://evil.example",
        {"access-control-allow-origin": "https://evil.example"},
    )

    assert len(issues) == 1
    assert issues[0].title == "CORS reflects arbitrary Origin"
    assert issues[0].severity == "high"


def test_credentials_with_reflected_origin_creates_critical_finding() -> None:
    issues = check_cors_headers(
        "https://example.com/api",
        "null",
        {
            "access-control-allow-origin": "null",
            "access-control-allow-credentials": "true",
        },
    )

    assert len(issues) == 1
    assert issues[0].title == "CORS reflects arbitrary Origin"
    assert issues[0].severity == "critical"
    assert "credentials=true" in (issues[0].evidence or "")


def test_credentials_with_wildcard_origin_is_high_severity() -> None:
    issues = check_cors_headers(
        "https://example.com/api",
        "https://evil.example",
        {
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        },
    )

    assert len(issues) == 1
    assert issues[0].title == "Wildcard CORS origin"
    assert issues[0].severity == "high"


def test_overly_permissive_methods_are_reported_when_exposed() -> None:
    issues = check_cors_headers(
        "https://example.com/api",
        "https://evil.example",
        {
            "access-control-allow-origin": "https://evil.example",
            "access-control-allow-methods": "GET, POST, PUT, DELETE",
        },
    )

    titles = {issue.title for issue in issues}
    assert "Overly permissive CORS methods" in titles


def test_safe_cors_response_has_no_finding() -> None:
    issues = check_cors_headers(
        "https://example.com/api",
        "https://evil.example",
        {
            "access-control-allow-origin": "https://app.example.com",
            "access-control-allow-methods": "GET, POST",
        },
    )

    assert issues == []
