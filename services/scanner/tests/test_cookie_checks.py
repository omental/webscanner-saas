from app.scanner.checks.cookies import check_cookie_security


def test_missing_secure_on_https_session_cookie_is_high_severity() -> None:
    issues = check_cookie_security(
        "https://example.com",
        {"set-cookie": "session=abc123; HttpOnly; SameSite=Lax"},
    )

    assert len(issues) == 1
    assert issues[0].title == "Cookie missing Secure attribute"
    assert issues[0].severity == "high"
    assert "cookie=session" in (issues[0].evidence or "")


def test_missing_httponly_on_session_cookie_is_high_severity() -> None:
    issues = check_cookie_security(
        "https://example.com",
        {"set-cookie": "PHPSESSID=abc123; Secure; SameSite=Lax"},
    )

    assert len(issues) == 1
    assert issues[0].title == "Cookie missing HttpOnly attribute"
    assert issues[0].severity == "high"


def test_missing_samesite_creates_medium_session_cookie_finding() -> None:
    issues = check_cookie_security(
        "https://example.com",
        {"set-cookie": "auth_token=abc123; Secure; HttpOnly"},
    )

    assert len(issues) == 1
    assert issues[0].title == "Cookie missing SameSite attribute"
    assert issues[0].severity == "medium"


def test_samesite_none_without_secure_is_high_severity() -> None:
    issues = check_cookie_security(
        "https://example.com",
        {"set-cookie": "sid=abc123; HttpOnly; SameSite=None"},
    )

    titles = {issue.title for issue in issues}
    assert "Cookie missing Secure attribute" in titles
    assert "Cookie uses SameSite=None without Secure" in titles
    assert any(
        issue.title == "Cookie uses SameSite=None without Secure"
        and issue.severity == "high"
        for issue in issues
    )


def test_cookie_evidence_redacts_values() -> None:
    issues = check_cookie_security(
        "https://example.com",
        {"set-cookie": "jwt=secret-token-value; Secure"},
    )

    evidence = " ".join(issue.evidence or "" for issue in issues)
    assert "secret-token-value" not in evidence
    assert "value=[redacted]" in evidence


def test_cookie_dedupe_key_is_stable_per_cookie_and_attribute() -> None:
    first = check_cookie_security(
        "https://example.com/login",
        {"set-cookie": "session=first; HttpOnly; SameSite=Lax"},
    )[0]
    second = check_cookie_security(
        "https://example.com/account",
        {"set-cookie": "session=second; HttpOnly; SameSite=Lax"},
    )[0]

    assert first.dedupe_key == second.dedupe_key


def test_secure_cookie_with_core_attributes_has_no_finding() -> None:
    assert (
        check_cookie_security(
            "https://example.com",
            {"set-cookie": "session=abc123; Secure; HttpOnly; SameSite=Lax"},
        )
        == []
    )


def test_obviously_broad_cookie_domain_is_reported() -> None:
    issues = check_cookie_security(
        "https://example.com",
        {"set-cookie": "session=abc123; Secure; HttpOnly; SameSite=Lax; Domain=.com"},
    )

    assert len(issues) == 1
    assert issues[0].title == "Cookie Domain appears overly broad"
    assert "domain=.com" in (issues[0].evidence or "")
