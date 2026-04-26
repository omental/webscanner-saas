from app.scanner.checks.auth_advanced import check_auth_advanced


LOGIN_FORM = """
<form method="post" action="/login">
  <input name="username" value="private">
  <input type="password" name="password" value="secret">
  <button>Log in</button>
</form>
"""


def test_detects_http_login_form() -> None:
    issues = check_auth_advanced(
        "http://example.com/login",
        LOGIN_FORM,
        {},
        200,
    )

    titles = {issue.title for issue in issues}
    assert "Login form submitted over insecure HTTP" in titles
    assert any(issue.severity == "high" for issue in issues)


def test_detects_http_form_action() -> None:
    issues = check_auth_advanced(
        "https://example.com/login",
        """
        <form method="post" action="http://example.com/login">
          <input name="username">
          <input type="password" name="password">
        </form>
        """,
        {"content-security-policy": "frame-ancestors 'self'", "strict-transport-security": "max-age=1"},
        200,
    )

    assert any(issue.title == "Login form posts to insecure HTTP" for issue in issues)


def test_detects_missing_login_csrf_token() -> None:
    issues = check_auth_advanced(
        "https://example.com/login",
        LOGIN_FORM,
        {"content-security-policy": "frame-ancestors 'self'", "strict-transport-security": "max-age=1"},
        200,
    )

    assert any(issue.title == "Login form missing CSRF token" for issue in issues)


def test_detects_auth_page_missing_clickjacking_protection() -> None:
    issues = check_auth_advanced(
        "https://example.com/account/login",
        """
        <form method="post" action="/account/login">
          <input name="csrf_token">
          <input type="password" name="password" autocomplete="current-password">
        </form>
        """,
        {"content-security-policy": "default-src 'self'", "strict-transport-security": "max-age=1"},
        200,
    )

    assert any(
        issue.title == "Auth page missing clickjacking protection"
        for issue in issues
    )


def test_detects_wp_login_as_informational() -> None:
    issues = check_auth_advanced(
        "https://example.com/wp-login.php",
        "<html>WordPress wp-submit</html>",
        {
            "content-security-policy": "frame-ancestors 'self'",
            "strict-transport-security": "max-age=1",
        },
        200,
    )

    assert any(
        issue.title == "WordPress login endpoint reachable"
        and issue.severity == "info"
        for issue in issues
    )


def test_does_not_flag_normal_non_auth_page() -> None:
    issues = check_auth_advanced(
        "https://example.com/about",
        "<html><h1>About</h1></html>",
        {},
        200,
    )

    assert issues == []


def test_evidence_does_not_store_cookie_values_or_input_values() -> None:
    issues = check_auth_advanced(
        "https://example.com/login",
        LOGIN_FORM,
        {
            "set-cookie": "PHPSESSID=super-secret; Path=/",
            "content-security-policy": "frame-ancestors 'self'",
        },
        200,
    )

    evidence = " ".join(issue.evidence or "" for issue in issues)
    assert "super-secret" not in evidence
    assert "private" not in evidence
    assert "secret" not in evidence
    assert "PHPSESSID" in evidence
    assert "username" in evidence
    assert "password" in evidence


def test_duplicate_prevention() -> None:
    issues = check_auth_advanced(
        "https://example.com/login",
        """
        <form method="post" action="/login">
          <input type="password" name="password">
        </form>
        <form method="post" action="/login">
          <input type="password" name="password2">
        </form>
        """,
        {},
        200,
    )
    missing_csrf = [
        issue for issue in issues if issue.title == "Login form missing CSRF token"
    ]

    assert len(missing_csrf) == 1


def test_exposed_admin_panel_without_login_indicators_is_medium() -> None:
    issues = check_auth_advanced(
        "https://example.com/admin",
        "<html><h1>Admin dashboard</h1></html>",
        {
            "content-security-policy": "frame-ancestors 'self'",
            "strict-transport-security": "max-age=1",
        },
        200,
    )

    assert any(
        issue.title == "Admin interface exposed" and issue.severity == "medium"
        for issue in issues
    )
