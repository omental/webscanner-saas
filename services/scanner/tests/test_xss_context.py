from app.services.xss_context import classify_xss_context


def test_marker_not_reflected() -> None:
    result = classify_xss_context("<p>safe</p>", "MARK")

    assert result["reflected"] is False
    assert result["context"] == "unknown"
    assert result["executable_context"] is False


def test_script_context_is_executable() -> None:
    result = classify_xss_context("<script>var x = 'MARK';</script>", "MARK")

    assert result["context"] == "javascript_string"
    assert result["executable_context"] is True


def test_attribute_context_is_executable() -> None:
    result = classify_xss_context('<a href="MARK">link</a>', "MARK")

    assert result["context"] == "html_attribute"
    assert result["executable_context"] is True


def test_html_body_dangerous_marker_is_executable() -> None:
    result = classify_xss_context("<p><img src=x></p>", "<img src=x>")

    assert result["context"] == "html_body"
    assert result["executable_context"] is True


def test_json_context_is_not_executable() -> None:
    result = classify_xss_context('{"value": "MARK"}', "MARK")

    assert result["context"] == "json_context"
    assert result["executable_context"] is False


def test_url_context_is_not_executable() -> None:
    result = classify_xss_context("<p>https://example.com/?q=MARK</p>", "MARK")

    assert result["context"] == "url_context"
    assert result["executable_context"] is False
