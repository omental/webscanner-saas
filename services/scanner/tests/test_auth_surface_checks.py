from app.scanner.checks.auth_surface import check_auth_surface


def test_detects_wp_login_page() -> None:
    issues = check_auth_surface(
        "https://example.com/wp-login.php",
        '<form id="loginform"><input name="log"><input type="password" name="pwd"></form>',
        {},
    )

    titles = {issue.title for issue in issues}
    assert "WordPress login surface detected" in titles
    assert all(issue.severity == "low" for issue in issues)


def test_detects_admin_url() -> None:
    issues = check_auth_surface("https://example.com/admin", "<html>Admin</html>", {})

    assert len(issues) == 1
    assert issues[0].title == "Admin surface detected"
    assert issues[0].severity == "low"


def test_detects_password_form() -> None:
    issues = check_auth_surface(
        "https://example.com/signin",
        """
        <form method="post" action="/session">
          <input name="email" value="user@example.com">
          <input type="password" name="password" value="secret">
        </form>
        """,
        {"set-cookie": "session=abc123; Secure; HttpOnly; SameSite=Lax"},
    )

    assert len(issues) == 1
    assert issues[0].title == "Login surface detected"
    assert "form_method=POST" in (issues[0].evidence or "")
    assert "session_cookies_observed=session" in (issues[0].evidence or "")


def test_normal_page_has_no_auth_surface_finding() -> None:
    issues = check_auth_surface(
        "https://example.com/about",
        "<html><h1>About</h1></html>",
        {},
    )

    assert issues == []


def test_auth_surface_evidence_does_not_store_input_values() -> None:
    issues = check_auth_surface(
        "https://example.com/login",
        """
        <form method="post" action="/login">
          <input name="email" value="private@example.com">
          <input type="password" name="password" value="top-secret">
        </form>
        """,
        {},
    )

    evidence = " ".join(issue.evidence or "" for issue in issues)
    assert "email" in evidence
    assert "password" in evidence
    assert "private@example.com" not in evidence
    assert "top-secret" not in evidence


def test_auth_surface_duplicate_prevention() -> None:
    issues = check_auth_surface(
        "https://example.com/login",
        """
        <form method="post" action="/login">
          <input type="password" name="password">
        </form>
        <form method="post" action="/login">
          <input type="password" name="password">
        </form>
        """,
        {},
    )

    login_issues = [issue for issue in issues if issue.title == "Login surface detected"]
    assert len(login_issues) == 2
    assert len({issue.dedupe_key for issue in login_issues}) == 2
