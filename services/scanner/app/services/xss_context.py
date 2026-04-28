import re


CONTEXT_UNKNOWN = "unknown"
CONTEXT_HTML_BODY = "html_body"
CONTEXT_HTML_ATTRIBUTE = "html_attribute"
CONTEXT_JAVASCRIPT_STRING = "javascript_string"
CONTEXT_URL = "url_context"
CONTEXT_JSON = "json_context"


def _result(reflected: bool, context: str, executable: bool, summary: str) -> dict:
    return {
        "reflected": reflected,
        "context": context,
        "executable_context": executable,
        "summary": summary,
    }


def _looks_json_like(text: str) -> bool:
    stripped = text.strip()
    return (
        (stripped.startswith("{") and stripped.endswith("}"))
        or (stripped.startswith("[") and stripped.endswith("]"))
    )


def _inside_script(text: str, index: int) -> bool:
    before = text[:index].lower()
    after = text[index:].lower()
    return before.rfind("<script") > before.rfind("</script") and "</script" in after


def _inside_tag_attribute(text: str, index: int) -> bool:
    last_open = text.rfind("<", 0, index)
    last_close = text.rfind(">", 0, index)
    if last_open <= last_close:
        return False
    next_close = text.find(">", index)
    if next_close == -1:
        return False
    tag_text = text[last_open : next_close + 1]
    return bool(re.search(r"\s[\w:-]+\s*=\s*['\"][^'\"]*$", tag_text[: index - last_open]))


def _inside_url_like_text(text: str, marker: str, index: int) -> bool:
    start = max(index - 80, 0)
    end = min(index + len(marker) + 80, len(text))
    surrounding = text[start:end]
    return bool(re.search(r"https?://|[?&][\w.-]+=", surrounding, re.IGNORECASE))


def _has_unescaped_dangerous_chars(marker: str) -> bool:
    return any(char in marker for char in ("<", ">", '"', "'", "`"))


def classify_xss_context(response_body: str, marker: str) -> dict:
    body = response_body or ""
    marker = marker or ""
    if not marker or marker not in body:
        return _result(False, CONTEXT_UNKNOWN, False, "marker was not reflected")

    index = body.find(marker)
    if _looks_json_like(body):
        return _result(True, CONTEXT_JSON, False, "marker reflected in JSON-like content")

    if _inside_script(body, index):
        return _result(True, CONTEXT_JAVASCRIPT_STRING, True, "marker reflected inside script content")

    if _inside_tag_attribute(body, index):
        return _result(True, CONTEXT_HTML_ATTRIBUTE, True, "marker reflected inside HTML attribute")

    if _inside_url_like_text(body, marker, index):
        return _result(True, CONTEXT_URL, False, "marker reflected inside URL-like text")

    executable = _has_unescaped_dangerous_chars(marker)
    summary = "marker reflected in HTML body"
    if executable:
        summary = f"{summary} with unescaped dangerous characters"
    return _result(True, CONTEXT_HTML_BODY, executable, summary)
