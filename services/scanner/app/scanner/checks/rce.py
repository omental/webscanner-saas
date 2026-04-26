import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

RCE_PARAM_NAMES = {
    "cmd",
    "command",
    "exec",
    "run",
    "ping",
    "host",
    "ip",
    "domain",
    "query",
    "template",
    "file",
    "path",
}
SKIP_PATH_MARKERS = (
    "/admin",
    "/login",
    "/wp-admin",
    "/wp-login.php",
    "/account",
    "/checkout",
    "/payment",
    "/upload",
)
RCE_PROBES = (
    ("template_curly", "scanner_marker_{{7*7}}"),
    ("template_dollar", "scanner_marker_${7*7}"),
    ("template_erb", "scanner_marker_<%= 7*7 %>"),
    ("shell_backtick_marker", "scanner_marker_`SCANNER_MARKER`"),
    ("shell_substitution_marker", "scanner_marker_$(SCANNER_MARKER)"),
)
COMMAND_ERROR_PATTERNS = (
    re.compile(r"template(?:syntax)?error", re.IGNORECASE),
    re.compile(r"template syntax error", re.IGNORECASE),
    re.compile(r"jinja2\.exceptions", re.IGNORECASE),
    re.compile(r"twig\\error", re.IGNORECASE),
    re.compile(r"erb::|actionview::template", re.IGNORECASE),
    re.compile(r"freemarker\.template", re.IGNORECASE),
    re.compile(r"velocityexception", re.IGNORECASE),
    re.compile(r"command execution", re.IGNORECASE),
    re.compile(r"child_process", re.IGNORECASE),
    re.compile(r"processbuilder", re.IGNORECASE),
    re.compile(r"shell_exec|popen\(|proc_open", re.IGNORECASE),
    re.compile(r"syntax error.*(?:near|unexpected token)", re.IGNORECASE),
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
class RceIssue:
    category: str
    title: str
    description: str
    severity: str
    remediation: str
    confidence: str | None
    evidence: str | None
    dedupe_key: str


@dataclass(frozen=True)
class RceSignal:
    title: str
    severity: str
    confidence: str
    evidence_type: str
    snippet: str


def rce_enabled(enabled: bool = False) -> bool:
    return enabled


def should_skip_rce_url(page_url: str) -> bool:
    path = urlsplit(page_url).path.lower()
    return any(marker in path for marker in SKIP_PATH_MARKERS)


def extract_rce_parameters(
    page_url: str,
    body_excerpt: str | None,
    *,
    max_params: int,
) -> list[str]:
    if should_skip_rce_url(page_url):
        return []

    query = parse_qs(urlsplit(page_url).query, keep_blank_values=True)
    params = {key for key in query if key.lower() in RCE_PARAM_NAMES}

    if body_excerpt:
        form_matches = list(_FORM_PATTERN.finditer(body_excerpt))
        for form_match in form_matches:
            method_match = _FORM_METHOD_PATTERN.search(form_match.group("attrs"))
            method = method_match.group(1).lower() if method_match else "get"
            if method != "get":
                continue
            params.update(
                match.group(1)
                for match in _INPUT_PATTERN.finditer(form_match.group("body"))
                if match.group(1).lower() in RCE_PARAM_NAMES
            )

        if not form_matches:
            params.update(
                match.group(1)
                for match in _INPUT_PATTERN.finditer(body_excerpt)
                if match.group(1).lower() in RCE_PARAM_NAMES
            )

    return sorted(params)[:max_params]


def build_rce_probe_url(page_url: str, param_name: str, probe: str) -> str:
    parts = urlsplit(page_url)
    query = parse_qs(parts.query, keep_blank_values=True)
    query[param_name] = [probe]
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(query, doseq=True), "")
    )


def _short_snippet(body: str, start: int, end: int) -> str:
    snippet_start = max(start - _SNIPPET_RADIUS, 0)
    snippet_end = min(end + _SNIPPET_RADIUS, len(body))
    snippet = body[snippet_start:snippet_end].replace("\n", " ").replace("\r", " ")
    return re.sub(r"\s+", " ", snippet).strip()


def classify_rce_signal(response_body: str | None) -> RceSignal | None:
    if not response_body:
        return None

    if "scanner_marker_49" in response_body:
        return RceSignal(
            title="Possible server-side template/code evaluation",
            severity="high",
            confidence="high",
            evidence_type="marker_transformed",
            snippet="scanner_marker_49",
        )

    for pattern in COMMAND_ERROR_PATTERNS:
        match = pattern.search(response_body)
        if match:
            return RceSignal(
                title="Possible command execution sink",
                severity="medium",
                confidence="medium",
                evidence_type="backend_error",
                snippet=_short_snippet(response_body, match.start(), match.end()),
            )

    return None


def check_rce_response(
    *,
    page_url: str,
    param_name: str,
    probe_family: str,
    response_body: str | None,
) -> list[RceIssue]:
    signal = classify_rce_signal(response_body)
    if signal is None:
        return []

    evidence = (
        f"url={page_url} parameter={param_name} probe_family={probe_family} "
        f"evidence_type={signal.evidence_type} snippet={signal.snippet}"
    )[:500]

    return [
        RceIssue(
            category="rce_signal",
            title=signal.title,
            description=(
                "An inert marker probe produced evidence of possible server-side "
                "template/code evaluation or unsafe command parsing."
            ),
            severity=signal.severity,
            remediation="Avoid evaluating user-controlled input and isolate command/template execution paths.",
            confidence=signal.confidence,
            evidence=evidence,
            dedupe_key=f"{page_url}:{param_name}:{signal.evidence_type}:rce-signal",
        )
    ]
