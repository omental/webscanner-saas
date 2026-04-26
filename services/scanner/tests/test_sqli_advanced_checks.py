from app.core.config import Settings
from app.scanner.checks.sqli_advanced import (
    ResponseSnapshot,
    advanced_sqli_enabled,
    boolean_probe_pairs_for_budget,
    build_advanced_sqli_probe_url,
    check_boolean_sqli,
    check_timing_sqli,
    extract_advanced_sqli_parameters,
)


def test_boolean_true_false_differential_detection() -> None:
    baseline = ResponseSnapshot(200, "<title>Item</title><p>record one</p>")
    true_response = ResponseSnapshot(200, "<title>Item</title><p>record one</p>")
    false_response = ResponseSnapshot(200, "<title>Item</title><p>No results</p>" + "x" * 500)

    issues = check_boolean_sqli(
        "https://example.com/item?id=1",
        "id",
        baseline,
        true_response,
        false_response,
        repeat_confirmed=True,
        dbms_hint="generic_boolean",
    )

    assert len(issues) == 1
    assert issues[0].category == "sqli_advanced"
    assert issues[0].title == "Possible boolean-based SQL injection"
    assert issues[0].severity == "high"
    assert issues[0].confidence == "high"
    assert "detection=boolean" in (issues[0].evidence or "")
    assert "payload" not in (issues[0].evidence or "").lower()


def test_no_finding_when_responses_are_similar() -> None:
    baseline = ResponseSnapshot(200, "<title>Search</title><p>same page</p>")
    true_response = ResponseSnapshot(200, "<title>Search</title><p>same page</p>")
    false_response = ResponseSnapshot(200, "<title>Search</title><p>same page</p>")

    issues = check_boolean_sqli(
        "https://example.com/search?q=test",
        "q",
        baseline,
        true_response,
        false_response,
        repeat_confirmed=True,
    )

    assert issues == []


def test_timing_detection_with_mocked_delays() -> None:
    issues = check_timing_sqli(
        "https://example.com/item?id=1",
        "id",
        ResponseSnapshot(200, "ok", 100),
        ResponseSnapshot(200, "ok", 3300),
        repeat_response=ResponseSnapshot(200, "ok", 3400),
        dbms_hint="mysql_time",
    )

    assert len(issues) == 1
    assert issues[0].title == "Possible time-based SQL injection"
    assert issues[0].severity == "high"
    assert issues[0].confidence == "high"
    assert "timing_delta_ms=3200" in (issues[0].evidence or "")


def test_max_param_limit_respected() -> None:
    params = extract_advanced_sqli_parameters(
        "https://example.com/search?id=1&q=a&page=2&category=x&extra=y",
        '<form><input name="search"><input name="cat"></form>',
        max_params=3,
    )

    assert len(params) == 3


def test_max_probe_limit_respected() -> None:
    assert len(boolean_probe_pairs_for_budget(1)) == 0
    assert len(boolean_probe_pairs_for_budget(2)) == 1
    assert len(boolean_probe_pairs_for_budget(4)) == 2


def test_probe_url_preserves_other_parameters() -> None:
    url = build_advanced_sqli_probe_url(
        "https://example.com/item?id=1&sort=asc",
        "id",
        "probe",
    )

    assert "id=probe" in url
    assert "sort=asc" in url


def test_duplicate_prevention_key_stable_for_same_page_param_detection() -> None:
    first = check_boolean_sqli(
        "https://example.com/item?id=1",
        "id",
        ResponseSnapshot(200, "<title>A</title>same"),
        ResponseSnapshot(200, "<title>A</title>same"),
        ResponseSnapshot(200, "<title>A</title>different" + "x" * 500),
        repeat_confirmed=True,
    )[0]
    second = check_boolean_sqli(
        "https://example.com/item?id=1",
        "id",
        ResponseSnapshot(200, "<title>A</title>same"),
        ResponseSnapshot(200, "<title>A</title>same"),
        ResponseSnapshot(200, "<title>A</title>different again" + "y" * 500),
        repeat_confirmed=True,
    )[0]

    assert first.dedupe_key == second.dedupe_key


def test_advanced_sqli_disabled_by_default() -> None:
    settings = Settings()

    assert settings.enable_advanced_sqli_checks is False
    assert advanced_sqli_enabled(settings.enable_advanced_sqli_checks) is False
