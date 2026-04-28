from app.services.payload_engine import get_payloads


def test_supported_vulnerability_types_return_payloads() -> None:
    for vulnerability_type in ("sqli", "xss", "ssrf", "rce"):
        assert get_payloads(vulnerability_type)


def test_quick_is_smaller_than_standard() -> None:
    assert len(get_payloads("sqli", "quick")) < len(get_payloads("sqli", "standard"))


def test_profiles_expand_payload_count() -> None:
    quick = len(get_payloads("xss", "quick"))
    standard = len(get_payloads("xss", "standard"))
    deep = len(get_payloads("xss", "deep"))
    aggressive = len(get_payloads("xss", "aggressive"))

    assert quick <= standard <= deep <= aggressive


def test_unknown_profile_defaults_to_standard() -> None:
    assert get_payloads("rce", "unknown") == get_payloads("rce", "standard")


def test_unknown_vulnerability_type_returns_empty_list() -> None:
    assert get_payloads("unknown", "standard") == []


def test_returns_copy_not_shared_list() -> None:
    first = get_payloads("ssrf", "quick")
    first.append("mutated")

    assert "mutated" not in get_payloads("ssrf", "quick")
