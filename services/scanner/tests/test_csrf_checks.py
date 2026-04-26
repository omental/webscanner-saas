from app.scanner.checks.csrf import check_csrf_forms


def test_post_form_missing_token_creates_finding() -> None:
    issues = check_csrf_forms(
        "https://example.com/account",
        """
        <form method="post" action="/settings">
          <input name="email" value="user@example.com">
        </form>
        """,
    )

    assert len(issues) == 1
    assert issues[0].category == "csrf"
    assert issues[0].title == "Missing CSRF token in form"
    assert issues[0].severity == "medium"
    assert "method=POST" in (issues[0].evidence or "")


def test_post_form_with_csrf_token_has_no_finding() -> None:
    issues = check_csrf_forms(
        "https://example.com/account",
        """
        <form method="post" action="/settings">
          <input type="hidden" name="csrf_token" value="secret">
          <input name="email" value="user@example.com">
        </form>
        """,
    )

    assert issues == []


def test_get_form_is_ignored() -> None:
    issues = check_csrf_forms(
        "https://example.com/search",
        '<form method="get" action="/search"><input name="q" value="cats"></form>',
    )

    assert issues == []


def test_third_party_action_is_ignored() -> None:
    issues = check_csrf_forms(
        "https://example.com/account",
        """
        <form method="post" action="https://payments.example.net/checkout">
          <input name="amount" value="10">
        </form>
        """,
    )

    assert issues == []


def test_login_form_missing_token_is_low_severity() -> None:
    issues = check_csrf_forms(
        "https://example.com/login",
        '<form method="post" action="/login"><input name="username"></form>',
    )

    assert len(issues) == 1
    assert issues[0].severity == "low"


def test_evidence_does_not_include_input_values() -> None:
    issues = check_csrf_forms(
        "https://example.com/account",
        """
        <form method="post" action="/settings">
          <input name="email" value="private@example.com">
          <input name="display_name" value="Private Name">
        </form>
        """,
    )

    evidence = issues[0].evidence or ""
    assert "email" in evidence
    assert "display_name" in evidence
    assert "private@example.com" not in evidence
    assert "Private Name" not in evidence


def test_duplicate_prevention_uses_page_action_and_method() -> None:
    html = """
    <form method="post" action="/settings"><input name="email"></form>
    <form method="post" action="/settings"><input name="display_name"></form>
    """
    issues = check_csrf_forms("https://example.com/account", html)

    assert len(issues) == 1
