import re
import secrets
from dataclasses import dataclass
from html import unescape
from urllib.parse import parse_qs, quote, urlencode, urlsplit, urlunsplit

REFLECTION_MARKER_PREFIX = "SCANNER_XSS_MARKER_"
_INPUT_PATTERN = re.compile(
    r'<input[^>]+name=["\']?([a-zA-Z0-9_-]+)["\']?', re.IGNORECASE
)
_FORM_PATTERN = re.compile(
    r"<form\b(?P<attrs>[^>]*)>(?P<body>.*?)</form\s*>",
    re.IGNORECASE | re.DOTALL,
)
_FORM_METHOD_PATTERN = re.compile(r'method\s*=\s*["\']?([a-zA-Z]+)', re.IGNORECASE)
_SCRIPT_PATTERN = re.compile(
    r"<script\b[^>]*>.*?</script\s*>", re.IGNORECASE | re.DOTALL
)
_TAG_PATTERN = re.compile(r"<[^>]*>")
_ATTRIBUTE_PATTERN = re.compile(
    r"""[\w:-]+\s*=\s*(?:"[^"]*{marker}[^"]*"|'[^']*{marker}[^']*'|[^\s"'=<>`]*{marker}[^\s"'=<>`]*)"""
)
_SNIPPET_RADIUS = 90


@dataclass(frozen=True)
class ReflectedXssIssue:
    category: str
    title: str
    description: str
    severity: str
    remediation: str
    confidence: str | None
    evidence: str | None
    dedupe_key: str


@dataclass(frozen=True)
class ReflectionMatch:
    context: str
    confidence: str
    evidence_marker: str
    raw_reflection: bool


def build_reflection_marker() -> str:
    return f"{REFLECTION_MARKER_PREFIX}{secrets.token_hex(8)}"


def extract_reflection_parameters(page_url: str, body_excerpt: str | None) -> list[str]:
    params = {
        key
        for key in parse_qs(urlsplit(page_url).query, keep_blank_values=True)
        if key
    }

    if body_excerpt:
        form_matches = list(_FORM_PATTERN.finditer(body_excerpt))
        for form_match in form_matches:
            method_match = _FORM_METHOD_PATTERN.search(form_match.group("attrs"))
            method = method_match.group(1).lower() if method_match else "get"
            if method == "get":
                params.update(
                    match.group(1)
                    for match in _INPUT_PATTERN.finditer(form_match.group("body"))
                )

        if not form_matches:
            params.update(
                match.group(1) for match in _INPUT_PATTERN.finditer(body_excerpt)
            )

    return sorted(params)


def build_reflection_probe_url(page_url: str, param_name: str, marker: str) -> str:
    parts = urlsplit(page_url)
    query = parse_qs(parts.query, keep_blank_values=True)
    query[param_name] = [marker]
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(query, doseq=True), "")
    )


def marker_is_reflected(marker: str, response_body: str | None) -> bool:
    return classify_reflection_context(marker, response_body) is not None


def _encoded_marker_variants(marker: str) -> set[str]:
    return {
        quote(marker, safe=""),
        "".join(f"&#{ord(character)};" for character in marker),
        "".join(f"&#x{ord(character):x};" for character in marker),
    }


def _short_snippet(body: str, marker: str) -> str:
    index = body.find(marker)
    if index < 0:
        return ""

    start = max(index - _SNIPPET_RADIUS, 0)
    end = min(index + len(marker) + _SNIPPET_RADIUS, len(body))
    snippet = body[start:end].replace("\n", " ").replace("\r", " ")
    return re.sub(r"\s+", " ", snippet).strip()


def _marker_is_in_script_block(marker: str, response_body: str) -> bool:
    return any(marker in match.group(0) for match in _SCRIPT_PATTERN.finditer(response_body))


def _marker_is_in_attribute(marker: str, response_body: str) -> bool:
    for match in _TAG_PATTERN.finditer(response_body):
        tag = match.group(0)
        if marker not in tag or tag.lower().startswith("</"):
            continue

        pattern = re.compile(
            _ATTRIBUTE_PATTERN.pattern.format(marker=re.escape(marker)),
            re.IGNORECASE,
        )
        if pattern.search(tag):
            return True

    return False


def _marker_is_inside_tag(marker: str, response_body: str) -> bool:
    return any(marker in match.group(0) for match in _TAG_PATTERN.finditer(response_body))


def classify_reflection_context(
    marker: str, response_body: str | None
) -> ReflectionMatch | None:
    if not response_body:
        return None

    if marker in response_body:
        if _marker_is_in_script_block(marker, response_body):
            return ReflectionMatch("script_block", "high", marker, True)

        if _marker_is_in_attribute(marker, response_body):
            return ReflectionMatch("html_attribute", "high", marker, True)

        if not _marker_is_inside_tag(marker, response_body):
            return ReflectionMatch("html_text", "medium", marker, True)

        return ReflectionMatch("unknown", "medium", marker, True)

    for encoded_marker in _encoded_marker_variants(marker):
        if encoded_marker and encoded_marker != marker and encoded_marker in response_body:
            return ReflectionMatch("unknown", "low", encoded_marker, False)

    if marker in unescape(response_body):
        return ReflectionMatch("unknown", "low", "", False)

    return None


def check_reflected_xss(
    page_url: str,
    param_name: str,
    marker: str,
    response_body: str | None,
) -> list[ReflectedXssIssue]:
    reflection = classify_reflection_context(marker, response_body)
    if reflection is None:
        return []

    snippet = ""
    if response_body and reflection.evidence_marker:
        snippet = _short_snippet(response_body, reflection.evidence_marker)
        if reflection.raw_reflection:
            snippet = snippet.replace(marker, "[marker]")

    evidence = (
        f"parameter={param_name} url={page_url} context={reflection.context}"
        f" raw={str(reflection.raw_reflection).lower()} snippet={snippet}"
    )[:500]

    return [
        ReflectedXssIssue(
            category="reflected_xss",
            title=f'Possible reflected XSS via "{param_name}" parameter',
            description=(
                "A safe inert probe marker supplied in a request parameter was "
                f"reflected in the response body in {reflection.context} context."
            ),
            severity="medium",
            remediation="Encode untrusted input in responses and validate or sanitize reflected parameters.",
            confidence=reflection.confidence,
            evidence=evidence,
            dedupe_key=f"{page_url}:{param_name}:{reflection.context}:reflected-xss",
        )
    ]
