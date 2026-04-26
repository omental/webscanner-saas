import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

SQLI_LIGHT_PROBES = ("'", '"', ")", "')")
_INPUT_PATTERN = re.compile(
    r'<input[^>]+name=["\']?([a-zA-Z0-9_-]+)["\']?', re.IGNORECASE
)
_FORM_PATTERN = re.compile(
    r"<form\b(?P<attrs>[^>]*)>(?P<body>.*?)</form\s*>",
    re.IGNORECASE | re.DOTALL,
)
_FORM_METHOD_PATTERN = re.compile(r'method\s*=\s*["\']?([a-zA-Z]+)', re.IGNORECASE)
_COMMON_SQL_PARAMS = {
    "id",
    "item",
    "page",
    "q",
    "query",
    "search",
    "category",
    "cat",
}
SQL_ERROR_SIGNATURES = (
    ("mysql", re.compile(r"you have an error in your sql syntax", re.IGNORECASE)),
    ("mysql", re.compile(r"warning:\s*mysql", re.IGNORECASE)),
    ("mysql", re.compile(r"mariadb server version for the right syntax", re.IGNORECASE)),
    ("postgresql", re.compile(r"postgresql.*error", re.IGNORECASE | re.DOTALL)),
    ("postgresql", re.compile(r"pg_query\(\):", re.IGNORECASE)),
    ("postgresql", re.compile(r"quoted string not properly terminated", re.IGNORECASE)),
    ("postgresql", re.compile(r"unterminated quoted string", re.IGNORECASE)),
    ("mssql", re.compile(r"unclosed quotation mark after the character string", re.IGNORECASE)),
    ("mssql", re.compile(r"microsoft ole db provider for sql server", re.IGNORECASE)),
    ("mssql", re.compile(r"odbc sql server driver", re.IGNORECASE)),
    ("oracle", re.compile(r"\bora-\d{5}\b", re.IGNORECASE)),
    ("oracle", re.compile(r"oracle error", re.IGNORECASE)),
    ("sqlite", re.compile(r"sqlite error", re.IGNORECASE)),
    ("sqlite", re.compile(r"sqlite3::", re.IGNORECASE)),
    ("sqlite", re.compile(r"near \".+?\": syntax error", re.IGNORECASE)),
    ("database", re.compile(r"sql syntax error", re.IGNORECASE)),
    ("database", re.compile(r"database error", re.IGNORECASE)),
    ("database", re.compile(r"sqlalchemy\.(?:exc\.)?\w+error", re.IGNORECASE)),
)
SQL_ERROR_PATTERNS = tuple(pattern.pattern for _, pattern in SQL_ERROR_SIGNATURES)
_SNIPPET_RADIUS = 80
_LENGTH_DELTA_RATIO = 0.35
_LENGTH_DELTA_MIN = 500


@dataclass(frozen=True)
class SqliLightIssue:
    category: str
    title: str
    description: str
    severity: str
    remediation: str
    confidence: str | None
    evidence: str | None
    dedupe_key: str


@dataclass(frozen=True)
class SqlErrorMatch:
    dbms: str
    pattern: str
    snippet: str


def extract_sqli_parameters(page_url: str, body_excerpt: str | None) -> list[str]:
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
                    if match.group(1).lower() in _COMMON_SQL_PARAMS
                )

        if not form_matches:
            params.update(
                match.group(1)
                for match in _INPUT_PATTERN.finditer(body_excerpt)
                if match.group(1).lower() in _COMMON_SQL_PARAMS
            )

    return sorted(
        key
        for key in params
        if key.lower() in _COMMON_SQL_PARAMS
        or key in parse_qs(urlsplit(page_url).query, keep_blank_values=True)
    )


def build_sqli_probe_url(page_url: str, param_name: str, probe: str) -> str:
    parts = urlsplit(page_url)
    query = parse_qs(parts.query, keep_blank_values=True)
    query[param_name] = [probe]
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(query, doseq=True), "")
    )


def find_sql_error_pattern(response_body: str | None) -> str | None:
    match = find_sql_error_match(response_body)
    return match.pattern if match else None


def _short_snippet(body: str, start: int, end: int) -> str:
    snippet_start = max(start - _SNIPPET_RADIUS, 0)
    snippet_end = min(end + _SNIPPET_RADIUS, len(body))
    snippet = body[snippet_start:snippet_end].replace("\n", " ").replace("\r", " ")
    return re.sub(r"\s+", " ", snippet).strip()


def find_sql_error_match(response_body: str | None) -> SqlErrorMatch | None:
    if not response_body:
        return None

    for dbms, pattern in SQL_ERROR_SIGNATURES:
        match = pattern.search(response_body)
        if match:
            return SqlErrorMatch(
                dbms=dbms,
                pattern=pattern.pattern,
                snippet=_short_snippet(response_body, match.start(), match.end()),
            )
    return None


def _has_response_anomaly(
    baseline_status_code: int | None,
    baseline_body: str | None,
    probe_status_code: int | None,
    probe_body: str | None,
) -> bool:
    if baseline_status_code is not None and probe_status_code is not None:
        if baseline_status_code < 500 <= probe_status_code:
            return True

    if baseline_body is None or probe_body is None:
        return False

    baseline_length = len(baseline_body)
    probe_length = len(probe_body)
    delta = abs(probe_length - baseline_length)
    threshold = max(int(max(baseline_length, 1) * _LENGTH_DELTA_RATIO), _LENGTH_DELTA_MIN)
    return delta >= threshold


def _probe_label(probe: str) -> str:
    if probe == "'":
        return "single_quote"
    if probe == '"':
        return "double_quote"
    if probe == ")":
        return "closing_parenthesis"
    return "quote_parenthesis"


def check_sqli_light(
    page_url: str,
    param_name: str,
    probe: str,
    response_body: str | None,
    *,
    baseline_status_code: int | None = None,
    baseline_body: str | None = None,
    probe_status_code: int | None = None,
) -> list[SqliLightIssue]:
    error_match = find_sql_error_match(response_body)
    if error_match is None:
        if not _has_response_anomaly(
            baseline_status_code,
            baseline_body,
            probe_status_code,
            response_body,
        ):
            return []

        return [
            SqliLightIssue(
                category="sqli_light",
                title=f'Possible SQL injection anomaly via "{param_name}" parameter',
                description=(
                    "A lightweight SQL probe caused a notable response change, "
                    "but no SQL error signature was detected."
                ),
                severity="medium",
                remediation=(
                    "Review parameter handling and ensure database access uses "
                    "parameterized queries."
                ),
                confidence="low",
                evidence=(
                    f"parameter={param_name} url={page_url} "
                    f"probe_type={_probe_label(probe)} "
                    f"baseline_status={baseline_status_code} "
                    f"probe_status={probe_status_code} "
                    f"baseline_length={len(baseline_body or '')} "
                    f"probe_length={len(response_body or '')}"
                )[:500],
                dedupe_key=f"{page_url}:{param_name}:response-anomaly:sqli-light",
            )
        ]

    if baseline_body and find_sql_error_match(baseline_body):
        return []

    return [
        SqliLightIssue(
            category="sqli_light",
            title=f'Possible SQL injection via "{param_name}" parameter',
            description=(
                "A lightweight SQL probe triggered a response containing a "
                f"{error_match.dbms} database error signature."
            ),
            severity="high",
            remediation="Use parameterized queries and suppress raw database errors in production responses.",
            confidence="high",
            evidence=(
                f"parameter={param_name} url={page_url} "
                f"probe_type={_probe_label(probe)} dbms={error_match.dbms} "
                f"snippet={error_match.snippet}"
            )[:500],
            dedupe_key=f"{page_url}:{param_name}:{error_match.dbms}:sqli-light",
        )
    ]
