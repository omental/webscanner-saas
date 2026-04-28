import difflib
import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from app.scanner.checks.sqli_light import extract_sqli_parameters
from app.services.confidence import finding_confidence_metadata

BOOLEAN_PROBE_PAIRS = (
    ("generic_boolean", "' AND '1'='1", "' AND '1'='2"),
    ("numeric_boolean", "1 AND 1=1", "1 AND 1=2"),
)
TIMING_PROBES = (
    ("mysql_time", "' AND SLEEP(3) AND '1'='1"),
    ("postgresql_time", "' AND pg_sleep(3) IS NULL AND '1'='1"),
)
_TITLE_PATTERN = re.compile(r"<title\b[^>]*>(.*?)</title\s*>", re.IGNORECASE | re.DOTALL)
_TAG_PATTERN = re.compile(r"<[^>]+>")
_SIGNIFICANT_LENGTH_RATIO = 0.25
_SIGNIFICANT_LENGTH_MIN = 250
_SIMILARITY_FLOOR = 0.94
_TIMING_THRESHOLD_MS = 2200


@dataclass(frozen=True)
class SqliAdvancedIssue:
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
class ResponseSnapshot:
    status_code: int | None
    body: str | None
    response_time_ms: int | None = None


def extract_advanced_sqli_parameters(
    page_url: str,
    body_excerpt: str | None,
    *,
    max_params: int,
) -> list[str]:
    return extract_sqli_parameters(page_url, body_excerpt)[:max_params]


def boolean_probe_pairs_for_budget(max_probes_per_param: int) -> tuple[tuple[str, str, str], ...]:
    pair_budget = max(max_probes_per_param, 0) // 2
    return BOOLEAN_PROBE_PAIRS[:pair_budget]


def advanced_sqli_enabled(enabled: bool = False) -> bool:
    return enabled


def build_advanced_sqli_probe_url(page_url: str, param_name: str, probe: str) -> str:
    parts = urlsplit(page_url)
    query = parse_qs(parts.query, keep_blank_values=True)
    query[param_name] = [probe]
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(query, doseq=True), "")
    )


def is_same_origin(left_url: str, right_url: str) -> bool:
    left = urlsplit(left_url)
    right = urlsplit(right_url)
    return (
        left.scheme.lower(),
        (left.hostname or "").lower(),
        left.port,
    ) == (
        right.scheme.lower(),
        (right.hostname or "").lower(),
        right.port,
    )


def _title(body: str | None) -> str:
    if not body:
        return ""
    match = _TITLE_PATTERN.search(body)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()


def _stable_text(body: str | None) -> str:
    if not body:
        return ""
    text = _TAG_PATTERN.sub(" ", body)
    return re.sub(r"\s+", " ", text).strip()[:4000]


def _length_delta(left: ResponseSnapshot, right: ResponseSnapshot) -> int:
    return abs(len(left.body or "") - len(right.body or ""))


def _similarity(left: ResponseSnapshot, right: ResponseSnapshot) -> float:
    left_text = _stable_text(left.body)
    right_text = _stable_text(right.body)
    if not left_text and not right_text:
        return 1.0
    return difflib.SequenceMatcher(None, left_text, right_text).ratio()


def _responses_similar(left: ResponseSnapshot, right: ResponseSnapshot) -> bool:
    if left.status_code != right.status_code:
        return False
    if _title(left.body) != _title(right.body):
        return False

    max_length = max(len(left.body or ""), len(right.body or ""), 1)
    delta = _length_delta(left, right)
    threshold = max(int(max_length * 0.08), 120)
    if delta > threshold:
        return False

    return _similarity(left, right) >= _SIMILARITY_FLOOR


def _responses_differ_significantly(
    baseline: ResponseSnapshot,
    false_response: ResponseSnapshot,
) -> bool:
    if baseline.status_code != false_response.status_code:
        return True
    if _title(baseline.body) != _title(false_response.body):
        return True

    max_length = max(len(baseline.body or ""), 1)
    delta = _length_delta(baseline, false_response)
    length_threshold = max(int(max_length * _SIGNIFICANT_LENGTH_RATIO), _SIGNIFICANT_LENGTH_MIN)
    if delta >= length_threshold:
        return True

    return _similarity(baseline, false_response) < 0.72


def check_boolean_sqli(
    page_url: str,
    param_name: str,
    baseline: ResponseSnapshot,
    true_response: ResponseSnapshot,
    false_response: ResponseSnapshot,
    *,
    repeat_confirmed: bool,
    dbms_hint: str | None = None,
) -> list[SqliAdvancedIssue]:
    if not _responses_similar(baseline, true_response):
        return []
    if not _responses_differ_significantly(baseline, false_response):
        return []

    severity = "high" if repeat_confirmed else "medium"
    confidence = "high" if repeat_confirmed else "medium"
    length_delta = _length_delta(true_response, false_response)
    evidence = (
        f"url={page_url} parameter={param_name} detection=boolean "
        f"true_false_length_delta={length_delta} "
        f"baseline_status={baseline.status_code} true_status={true_response.status_code} "
        f"false_status={false_response.status_code} dbms_hint={dbms_hint or '-'}"
    )[:500]
    metadata = finding_confidence_metadata(
        context_validated=repeat_confirmed,
        payload_reflected=True,
        weak_signal_count=0 if repeat_confirmed else 1,
        payload_used=dbms_hint or "boolean_probe_pair",
        affected_parameter=param_name,
        response_snippet=(false_response.body or "")[:240],
        request_url=page_url,
        http_method="GET",
        tested_parameter=param_name,
        payload=dbms_hint or "boolean_probe_pair",
        baseline_status_code=baseline.status_code,
        attack_status_code=false_response.status_code,
        baseline_response_size=len(baseline.body) if baseline.body is not None else None,
        attack_response_size=len(false_response.body) if false_response.body is not None else None,
        baseline_response_time_ms=baseline.response_time_ms,
        attack_response_time_ms=false_response.response_time_ms,
        response_diff_summary=(
            f"true_false_length_delta={length_delta}; "
            f"baseline_status={baseline.status_code}; false_status={false_response.status_code}"
        ),
        verification_steps=[
            "Replay the true and false boolean probes.",
            "Confirm the false probe response differs while the true probe matches baseline.",
            "Repeat the probe pair to rule out dynamic content drift.",
        ],
        false_positive_notes="Dynamic pages, personalization, or caching can mimic boolean response differences.",
    )

    return [
        SqliAdvancedIssue(
            category="sqli_advanced",
            title="Possible boolean-based SQL injection",
            description=(
                "Paired safe boolean probes produced a repeatable differential response "
                "while preserving all other parameters."
            ),
            severity=severity,
            remediation="Use parameterized queries and validate numeric/string parameters server-side.",
            confidence=confidence,
            evidence=evidence,
            dedupe_key=f"{page_url}:{param_name}:boolean:sqli-advanced",
            **metadata,
        )
    ]


def check_timing_sqli(
    page_url: str,
    param_name: str,
    baseline: ResponseSnapshot,
    timing_response: ResponseSnapshot,
    *,
    repeat_response: ResponseSnapshot | None = None,
    dbms_hint: str | None = None,
) -> list[SqliAdvancedIssue]:
    baseline_time = baseline.response_time_ms or 0
    timing_delta = (timing_response.response_time_ms or 0) - baseline_time
    repeat_delta = None
    if repeat_response is not None:
        repeat_delta = (repeat_response.response_time_ms or 0) - baseline_time

    confirmed = (
        timing_delta >= _TIMING_THRESHOLD_MS
        and repeat_delta is not None
        and repeat_delta >= _TIMING_THRESHOLD_MS
    )
    partial = timing_delta >= _TIMING_THRESHOLD_MS
    if not confirmed and not partial:
        return []

    severity = "high" if confirmed else "medium"
    confidence = "high" if confirmed else "medium"
    evidence = (
        f"url={page_url} parameter={param_name} detection=timing "
        f"timing_delta_ms={timing_delta} repeat_delta_ms={repeat_delta if repeat_delta is not None else '-'} "
        f"dbms_hint={dbms_hint or '-'}"
    )[:500]
    metadata = finding_confidence_metadata(
        time_based_confirmation=confirmed,
        weak_signal_count=0 if confirmed else 2,
        payload_used=dbms_hint or "timing_probe",
        affected_parameter=param_name,
        request_url=page_url,
        http_method="GET",
        tested_parameter=param_name,
        payload=dbms_hint or "timing_probe",
        baseline_status_code=baseline.status_code,
        attack_status_code=timing_response.status_code,
        baseline_response_size=len(baseline.body) if baseline.body is not None else None,
        attack_response_size=len(timing_response.body) if timing_response.body is not None else None,
        baseline_response_time_ms=baseline.response_time_ms,
        attack_response_time_ms=timing_response.response_time_ms,
        response_diff_summary=(
            f"timing_delta_ms={timing_delta}; "
            f"repeat_delta_ms={repeat_delta if repeat_delta is not None else '-'}"
        ),
        verification_steps=[
            "Replay the baseline and timing probe requests.",
            "Repeat the timing probe and compare latency against baseline.",
        ],
        false_positive_notes="Network latency or backend load can cause false timing signals without repeat confirmation.",
    )

    return [
        SqliAdvancedIssue(
            category="sqli_advanced",
            title="Possible time-based SQL injection",
            description=(
                "A bounded timing probe caused a notable response delay. "
                "No data extraction was attempted."
            ),
            severity=severity,
            remediation="Use parameterized queries and avoid executing user-controlled SQL expressions.",
            confidence=confidence,
            evidence=evidence,
            dedupe_key=f"{page_url}:{param_name}:timing:sqli-advanced",
            **metadata,
        )
    ]
