import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

REDIRECT_PARAM_NAMES = {
    "next": "next",
    "url": "url",
    "redirect": "redirect",
    "return": "return",
    "returnto": "returnTo",
    "continue": "continue",
    "destination": "destination",
}
REDIRECT_PROBE_URL = "https://example.com/webscanner-open-redirect-check"
_INPUT_NAME_PATTERN = re.compile(
    r'<input\b[^>]*\bname\s*=\s*["\']?([a-zA-Z0-9_-]+)["\']?',
    re.IGNORECASE,
)


@dataclass(frozen=True)
class OpenRedirectIssue:
    category: str
    title: str
    description: str
    severity: str
    remediation: str
    confidence: str | None
    evidence: str | None
    dedupe_key: str


def extract_redirect_parameters(page_url: str, body_excerpt: str | None) -> list[str]:
    params = {
        REDIRECT_PARAM_NAMES[key.lower()]
        for key in parse_qs(urlsplit(page_url).query, keep_blank_values=True)
        if key.lower() in REDIRECT_PARAM_NAMES
    }

    if body_excerpt:
        params.update(
            REDIRECT_PARAM_NAMES[match.group(1).lower()]
            for match in _INPUT_NAME_PATTERN.finditer(body_excerpt)
            if match.group(1).lower() in REDIRECT_PARAM_NAMES
        )

    return sorted(params)


def build_redirect_probe_url(page_url: str, param_name: str, probe_url: str) -> str:
    parts = urlsplit(page_url)
    query = parse_qs(parts.query, keep_blank_values=True)
    query[param_name] = [probe_url]
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(query, doseq=True), "")
    )


def check_open_redirect(
    page_url: str,
    param_name: str,
    location_header: str | None,
    final_url: str | None,
    probe_url: str = REDIRECT_PROBE_URL,
) -> list[OpenRedirectIssue]:
    observed = location_header or final_url
    if not observed:
        return []

    observed_parts = urlsplit(observed)
    probe_parts = urlsplit(probe_url)
    page_host = (urlsplit(page_url).hostname or "").lower()
    observed_host = (observed_parts.hostname or "").lower()

    if observed_parts.scheme not in {"http", "https"}:
        return []

    if observed_host != (probe_parts.hostname or "").lower():
        return []

    if observed_host == page_host:
        return []

    return [
        OpenRedirectIssue(
            category="open_redirect",
            title=f'Possible open redirect via "{param_name}" parameter',
            description="A redirect parameter appears to allow navigation to an external destination.",
            severity="medium",
            remediation="Restrict redirect targets to trusted internal paths or an explicit allowlist.",
            confidence="medium",
            evidence=observed[:240],
            dedupe_key=f"{page_url}:{param_name}:open-redirect",
        )
    ]
