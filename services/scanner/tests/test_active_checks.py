from app.scanner.checks.open_redirect import (
    REDIRECT_PROBE_URL,
    build_redirect_probe_url,
    check_open_redirect,
    extract_redirect_parameters,
)
from app.scanner.checks.reflected_xss import (
    build_reflection_marker,
    build_reflection_probe_url,
    check_reflected_xss,
    classify_reflection_context,
    extract_reflection_parameters,
    marker_is_reflected,
)
from app.scanner.checks.sqli_light import (
    SQLI_LIGHT_PROBES,
    build_sqli_probe_url,
    check_sqli_light,
    extract_sqli_parameters,
    find_sql_error_match,
    find_sql_error_pattern,
)


def test_redirect_parameter_detection_and_deduping() -> None:
    params = extract_redirect_parameters(
        "https://app.example/login?next=/dashboard",
        '<form><input name="next"><input name="returnTo"></form>',
    )

    assert params == ["next", "returnTo"]


def test_redirect_parameter_matching_is_exact_and_case_insensitive() -> None:
    params = extract_redirect_parameters(
        "https://app.example/login?return=/home&returnTo=/dashboard&myreturn=/x&redirect_url=/y",
        (
            '<form><input name="RETURN">'
            '<input name="returnTo">'
            '<input name="myreturn">'
            '<input name="redirect_url">'
            '<input name="continue">'
            '<input name="destination"></form>'
        ),
    )

    assert params == ["continue", "destination", "return", "returnTo"]


def test_open_redirect_issue_generation() -> None:
    issues = check_open_redirect(
        "https://app.example/login",
        "next",
        REDIRECT_PROBE_URL,
        None,
    )

    assert len(issues) == 1
    assert issues[0].category == "open_redirect"


def test_reflection_marker_detection() -> None:
    marker = build_reflection_marker()
    assert marker.startswith("SCANNER_XSS_MARKER_")
    assert marker_is_reflected(marker, f"hello {marker} world")
    issues = check_reflected_xss(
        "https://app.example/search",
        "q",
        marker,
        f"<html>{marker}</html>",
    )

    assert len(issues) == 1
    assert issues[0].category == "reflected_xss"
    assert issues[0].confidence == "medium"
    assert "context=html_body" in (issues[0].evidence or "")


def test_reflection_parameter_detection_dedupes_inputs() -> None:
    params = extract_reflection_parameters(
        "https://app.example/search?q=test",
        (
            '<form><input name="q"><input name="term"></form>'
            '<form method="post"><input name="csrf_token"></form>'
        ),
    )

    assert params == ["q", "term"]


def test_sql_error_pattern_detection() -> None:
    pattern = find_sql_error_pattern("You have an error in your SQL syntax near ''")
    issues = check_sqli_light(
        "https://app.example/item",
        "id",
        SQLI_LIGHT_PROBES[0],
        "Warning: MySQL error. You have an error in your SQL syntax",
        baseline_body="normal item page",
    )

    assert pattern == "you have an error in your sql syntax"
    assert len(issues) == 1
    assert issues[0].category == "sqli_light"
    assert issues[0].severity == "high"


def test_probe_url_builders() -> None:
    marker = build_reflection_marker()
    assert "next=" in build_redirect_probe_url(
        "https://app.example/login", "next", REDIRECT_PROBE_URL
    )
    assert "q=" in build_reflection_probe_url(
        "https://app.example/search", "q", marker
    )
    assert "id=" in build_sqli_probe_url(
        "https://app.example/item", "id", SQLI_LIGHT_PROBES[0]
    )


def test_sqli_parameter_detection() -> None:
    params = extract_sqli_parameters(
        "https://app.example/item?id=1",
        (
            '<form><input name="search"><input name="csrf_token"></form>'
            '<form method="post"><input name="q"></form>'
        ),
    )

    assert params == ["id", "search"]


def test_sqli_postgresql_error_detection() -> None:
    match = find_sql_error_match("PostgreSQL ERROR: unterminated quoted string")
    issues = check_sqli_light(
        "https://app.example/search",
        "q",
        SQLI_LIGHT_PROBES[0],
        "PostgreSQL ERROR: unterminated quoted string",
        baseline_body="normal search page",
    )

    assert match is not None
    assert match.dbms == "postgresql"
    assert len(issues) == 1
    assert "dbms=postgresql" in (issues[0].evidence or "")
    assert issues[0].confidence == "high"


def test_sqli_mssql_error_detection() -> None:
    match = find_sql_error_match(
        "Microsoft OLE DB Provider for SQL Server: Unclosed quotation mark after the character string"
    )

    assert match is not None
    assert match.dbms == "mssql"


def test_sqli_sqlite_error_detection() -> None:
    match = find_sql_error_match('SQLite error near "\'": syntax error')

    assert match is not None
    assert match.dbms == "sqlite"


def test_sqli_normal_response_has_no_finding() -> None:
    issues = check_sqli_light(
        "https://app.example/item",
        "id",
        SQLI_LIGHT_PROBES[0],
        "<html>normal item page</html>",
        baseline_status_code=200,
        baseline_body="<html>normal item page</html>",
        probe_status_code=200,
    )

    assert issues == []


def test_sqli_response_anomaly_without_sql_error_is_not_high_severity() -> None:
    issues = check_sqli_light(
        "https://app.example/item",
        "id",
        SQLI_LIGHT_PROBES[0],
        "short",
        baseline_status_code=200,
        baseline_body="x" * 2000,
        probe_status_code=500,
    )

    assert len(issues) == 1
    assert issues[0].severity == "medium"
    assert issues[0].confidence == "low"


def test_sqli_dedupe_key_is_stable_for_same_page_param_dbms() -> None:
    first = check_sqli_light(
        "https://app.example/item",
        "id",
        "'",
        "Warning: MySQL error. You have an error in your SQL syntax near quote",
        baseline_body="normal page",
    )[0]
    second = check_sqli_light(
        "https://app.example/item",
        "id",
        '"',
        "Warning: MySQL error. You have an error in your SQL syntax near double quote",
        baseline_body="normal page",
    )[0]

    assert first.dedupe_key == second.dedupe_key


def test_reflected_xss_attribute_context_is_high_confidence() -> None:
    marker = "SCANNER_XSS_MARKER_attr"
    issues = check_reflected_xss(
        "https://app.example/search",
        "q",
        marker,
        f'<input value="{marker}">',
    )

    assert len(issues) == 1
    assert issues[0].confidence == "high"
    assert issues[0].dedupe_key.endswith(":q:html_attribute:reflected-xss")
    assert "context=html_attribute" in (issues[0].evidence or "")
    assert marker not in (issues[0].evidence or "")


def test_reflected_xss_script_block_context_is_high_confidence() -> None:
    marker = "SCANNER_XSS_MARKER_script"
    reflection = classify_reflection_context(
        marker,
        f"<script>window.search = '{marker}'</script>",
    )

    assert reflection is not None
    assert reflection.context == "javascript_string"
    assert reflection.confidence == "high"


def test_escaped_reflected_xss_marker_is_low_confidence() -> None:
    marker = "SCANNER_XSS_MARKER_escaped"
    encoded_marker = "".join(f"&#{ord(character)};" for character in marker)
    issues = check_reflected_xss(
        "https://app.example/search",
        "q",
        marker,
        f"<p>{encoded_marker}</p>",
    )

    assert len(issues) == 1
    assert issues[0].confidence == "low"
    assert "raw=false" in (issues[0].evidence or "")


def test_reflected_xss_dedupe_key_is_stable_for_same_page_param_context() -> None:
    first_marker = "SCANNER_XSS_MARKER_first"
    second_marker = "SCANNER_XSS_MARKER_second"

    first = check_reflected_xss(
        "https://app.example/search",
        "q",
        first_marker,
        f"<p>{first_marker}</p>",
    )[0]
    second = check_reflected_xss(
        "https://app.example/search",
        "q",
        second_marker,
        f"<p>{second_marker}</p>",
    )[0]

    assert first.dedupe_key == second.dedupe_key
    assert first.evidence == second.evidence
