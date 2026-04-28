import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from app.services.confidence import finding_confidence_metadata

SSRF_PARAM_NAMES = {
    "url",
    "uri",
    "link",
    "target",
    "endpoint",
    "feed",
    "callback",
    "webhook",
    "image",
    "avatar",
    "file",
    "path",
    "redirect",
    "next",
}
BLOCKED_SCHEMES = {"file", "gopher", "ftp", "dict", "ldap"}
BLOCKED_HOSTS = {"localhost"}
FETCH_ERROR_PATTERNS = (
    re.compile(r"failed to fetch", re.IGNORECASE),
    re.compile(r"could not fetch", re.IGNORECASE),
    re.compile(r"error fetching", re.IGNORECASE),
    re.compile(r"upstream request failed", re.IGNORECASE),
    re.compile(r"proxy error", re.IGNORECASE),
    re.compile(r"connection refused", re.IGNORECASE),
    re.compile(r"connect\s+econnrefused", re.IGNORECASE),
    re.compile(r"curl error", re.IGNORECASE),
    re.compile(r"requests\.(?:exceptions\.)?\w+", re.IGNORECASE),
)
_INPUT_PATTERN = re.compile(
    r'<input[^>]+name=["\']?([a-zA-Z0-9_-]+)["\']?', re.IGNORECASE
)
_FORM_PATTERN = re.compile(
    r"<form\b(?P<attrs>[^>]*)>(?P<body>.*?)</form\s*>",
    re.IGNORECASE | re.DOTALL,
)
_FORM_METHOD_PATTERN = re.compile(r'method\s*=\s*["\']?([a-zA-Z]+)', re.IGNORECASE)
_SNIPPET_RADIUS = 90


@dataclass(frozen=True)
class SsrfIssue:
    category: str
    title: str
    description: str
    severity: str
    remediation: str
    confidence: str | None
    evidence: str | None
    dedupe_key: str
    confidence_level: str | None = None
    confidence_score: int | None = None
    evidence_type: str | None = None
    verification_steps: list[str] | None = None
    payload_used: str | None = None
    affected_parameter: str | None = None
    response_snippet: str | None = None
    false_positive_notes: str | None = None
    request_url: str | None = None
    http_method: str | None = None
    tested_parameter: str | None = None
    payload: str | None = None
    baseline_status_code: int | None = None
    attack_status_code: int | None = None
    baseline_response_size: int | None = None
    attack_response_size: int | None = None
    baseline_response_time_ms: int | None = None
    attack_response_time_ms: int | None = None
    response_diff_summary: str | None = None


@dataclass(frozen=True)
class SsrfEvidence:
    kind: str
    confidence: str
    severity: str
    snippet: str


def ssrf_enabled(enabled: bool = False) -> bool:
    return enabled


def extract_ssrf_parameters(
    page_url: str,
    body_excerpt: str | None,
    *,
    max_params: int,
) -> list[str]:
    query = parse_qs(urlsplit(page_url).query, keep_blank_values=True)
    params = {key for key in query if key.lower() in SSRF_PARAM_NAMES}

    if body_excerpt:
        for form_match in _FORM_PATTERN.finditer(body_excerpt):
            method_match = _FORM_METHOD_PATTERN.search(form_match.group("attrs"))
            method = method_match.group(1).lower() if method_match else "get"
            if method != "get":
                continue
            params.update(
                match.group(1)
                for match in _INPUT_PATTERN.finditer(form_match.group("body"))
                if match.group(1).lower() in SSRF_PARAM_NAMES
            )

        if not list(_FORM_PATTERN.finditer(body_excerpt)):
            params.update(
                match.group(1)
                for match in _INPUT_PATTERN.finditer(body_excerpt)
                if match.group(1).lower() in SSRF_PARAM_NAMES
            )

    return sorted(params)[:max_params]


def _host_is_blocked(hostname: str | None) -> bool:
    if not hostname:
        return True
    normalized = hostname.strip().lower().rstrip(".")
    if normalized in BLOCKED_HOSTS:
        return True

    try:
        ip = ipaddress.ip_address(normalized)
    except ValueError:
        return False

    return (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def is_safe_ssrf_probe_url(probe_url: str) -> bool:
    parts = urlsplit(probe_url)
    if parts.scheme.lower() in BLOCKED_SCHEMES:
        return False
    if parts.scheme.lower() not in {"http", "https"}:
        return False
    return not _host_is_blocked(parts.hostname)


def callback_domain(callback_url: str | None) -> str:
    if not callback_url:
        return "-"
    return urlsplit(callback_url).hostname or "-"


def build_ssrf_probe_url(
    page_url: str,
    param_name: str,
    callback_url: str,
) -> str | None:
    if not is_safe_ssrf_probe_url(callback_url):
        return None

    parts = urlsplit(page_url)
    query = parse_qs(parts.query, keep_blank_values=True)
    query[param_name] = [callback_url]
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(query, doseq=True), "")
    )


def _short_snippet(body: str, start: int, end: int) -> str:
    snippet_start = max(start - _SNIPPET_RADIUS, 0)
    snippet_end = min(end + _SNIPPET_RADIUS, len(body))
    snippet = body[snippet_start:snippet_end].replace("\n", " ").replace("\r", " ")
    return re.sub(r"\s+", " ", snippet).strip()


def find_ssrf_response_evidence(
    response_body: str | None,
    *,
    callback_url: str | None = None,
    callback_confirmed: bool = False,
) -> SsrfEvidence | None:
    if callback_confirmed:
        return SsrfEvidence("callback_confirmed", "high", "high", "")

    if not response_body:
        return None

    for pattern in FETCH_ERROR_PATTERNS:
        match = pattern.search(response_body)
        if match:
            return SsrfEvidence(
                "backend_fetch_error",
                "medium",
                "medium",
                _short_snippet(response_body, match.start(), match.end()),
            )

    return None


def check_ssrf_response(
    *,
    page_url: str,
    param_name: str,
    callback_url: str | None,
    response_body: str | None,
    callback_confirmed: bool = False,
) -> list[SsrfIssue]:
    evidence_match = find_ssrf_response_evidence(
        response_body,
        callback_url=callback_url,
        callback_confirmed=callback_confirmed,
    )
    if evidence_match is None:
        return []

    callback_host = callback_domain(callback_url)
    evidence = (
        f"url={page_url} parameter={param_name} probe_type=safe_callback "
        f"callback_domain={callback_host} evidence_type={evidence_match.kind} "
        f"snippet={evidence_match.snippet}"
    )[:500]
    metadata = finding_confidence_metadata(
        oob_callback_received=callback_confirmed,
        known_error_signature=not callback_confirmed,
        weak_signal_count=0 if callback_confirmed else 1,
        payload_used=callback_url,
        affected_parameter=param_name,
        response_snippet=evidence_match.snippet[:240],
        request_url=page_url,
        http_method="GET",
        tested_parameter=param_name,
        payload=callback_url,
        attack_response_size=len(response_body) if response_body is not None else None,
        response_diff_summary=(
            f"evidence_type={evidence_match.kind}; callback_domain={callback_host}"
        ),
        verification_steps=[
            "Replay the request with a safe external callback URL.",
            "Confirm a backend fetch error or out-of-band callback is tied to the request.",
            "Verify the callback URL is controlled and not an internal network target.",
        ],
        false_positive_notes="Fetch errors without callbacks can be caused by normal URL validation or proxy behavior.",
    )

    return [
        SsrfIssue(
            category="ssrf",
            title="Possible SSRF via URL parameter",
            description=(
                "A URL-like parameter showed evidence of backend fetch or proxy behavior "
                "when supplied with a configured safe callback URL."
            ),
            severity=evidence_match.severity,
            remediation="Restrict server-side fetch destinations with allowlists and block internal network ranges.",
            confidence=evidence_match.confidence,
            evidence=evidence,
            dedupe_key=f"{page_url}:{param_name}:ssrf",
            **metadata,
        )
    ]
