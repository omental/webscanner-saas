import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from app.services.response_diff import compare_responses

SQLI_TRUE_PAYLOAD = "' OR '1'='1"
SQLI_FALSE_PAYLOAD = "' AND '1'='2"
SQLI_PAYLOAD = SQLI_TRUE_PAYLOAD
SQLI_TIME_PAYLOADS = (
    "' OR SLEEP(3)-- ",
    "' OR pg_sleep(3)-- ",
    "'; WAITFOR DELAY '0:0:3'--",
)
TIME_DELAY_DELTA_MS = 2500
TIME_DELAY_MIN_MS = 2800
SQL_ERROR_PATTERNS = (
    re.compile(r"you have an error in your sql syntax", re.IGNORECASE),
    re.compile(r"warning:\s*mysql", re.IGNORECASE),
    re.compile(r"postgresql.*error", re.IGNORECASE | re.DOTALL),
    re.compile(r"pg_query\(\):", re.IGNORECASE),
    re.compile(r"unclosed quotation mark", re.IGNORECASE),
    re.compile(r"odbc sql server driver", re.IGNORECASE),
    re.compile(r"\bora-\d{5}\b", re.IGNORECASE),
    re.compile(r"oracle error", re.IGNORECASE),
    re.compile(r"sqlite error", re.IGNORECASE),
    re.compile(r"sql syntax error", re.IGNORECASE),
    re.compile(r"database error", re.IGNORECASE),
)


@dataclass(frozen=True)
class SqliIssue:
    category: str
    title: str
    description: str
    severity: str
    remediation: str
    confidence: str | None
    evidence: str | None
    dedupe_key: str
    confidence_level: str | None = None
    response_snippet: str | None = None
    request_url: str | None = None
    http_method: str | None = None
    tested_parameter: str | None = None
    payload_used: str | None = None
    payload: str | None = None
    evidence_type: str | None = None
    baseline_status_code: int | None = None
    attack_status_code: int | None = None
    baseline_response_size: int | None = None
    attack_response_size: int | None = None
    baseline_response_time_ms: int | None = None
    attack_response_time_ms: int | None = None
    response_diff_summary: str | None = None
    confidence_score: int | None = None
    false_positive_notes: str | None = None


def build_sqli_probe_url(page_url: str, param_name: str, payload: str = SQLI_PAYLOAD) -> str:
    parts = urlsplit(page_url)
    query = parse_qs(parts.query, keep_blank_values=True)
    query[param_name] = [payload]
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(query, doseq=True), "")
    )


def _has_sql_error(body: str | None) -> bool:
    if not body:
        return False
    return any(pattern.search(body) for pattern in SQL_ERROR_PATTERNS)


def _snippet(body: str | None) -> str | None:
    if not body:
        return None
    return re.sub(r"\s+", " ", body).strip()[:240]


def _signal_rank(signal: str | None) -> int:
    return {"none": 0, "weak": 1, "medium": 2, "strong": 3}.get(str(signal), 0)


def _behavioral_signal(baseline_true_diff: dict, true_false_diff: dict) -> tuple[str, str]:
    baseline_true_signal = baseline_true_diff.get("confidence_signal")
    true_false_signal = true_false_diff.get("confidence_signal")
    true_false_rank = _signal_rank(true_false_signal)
    baseline_true_rank = _signal_rank(baseline_true_signal)

    if true_false_signal == "strong":
        return "strong", "TRUE and FALSE payload responses differ strongly"
    if baseline_true_rank <= 1 and true_false_rank >= 2:
        return "strong", "TRUE response is close to baseline while FALSE differs"
    if true_false_signal == "medium":
        return "medium", "TRUE and FALSE payload responses differ meaningfully"
    if true_false_signal == "weak" or baseline_true_signal == "weak":
        return "weak", "weak boolean response difference observed"
    return "none", "no boolean response difference observed"


def _response_time(response) -> int:
    return int(getattr(response, "response_time_ms", 0) or 0)


def _is_time_delay(baseline, attack) -> bool:
    baseline_time = _response_time(baseline)
    attack_time = _response_time(attack)
    return (
        attack_time >= baseline_time + TIME_DELAY_DELTA_MS
        and attack_time >= TIME_DELAY_MIN_MS
    )


def _issue_from_timing(
    page_url: str,
    param_name: str,
    payload: str,
    baseline,
    attack,
    *,
    confirmed: bool,
) -> SqliIssue:
    baseline_time = _response_time(baseline)
    attack_time = _response_time(attack)
    timing_delta_ms = attack_time - baseline_time
    summary = (
        f"timing confirmation payload={payload}; baseline_ms={baseline_time}; "
        f"attack_ms={attack_time}; delta_ms={timing_delta_ms}; "
        f"confirmed={str(confirmed).lower()}"
    )
    return SqliIssue(
        category="sqli",
        title=f'Time-based SQL injection via "{param_name}" parameter',
        description=(
            "A SQL injection timing payload caused a controlled delay compared "
            "with the baseline response."
        ),
        severity="high" if confirmed else "medium",
        remediation="Use parameterized queries and avoid string concatenation in database access.",
        confidence="high" if confirmed else "medium",
        confidence_level="confirmed" if confirmed else "medium",
        confidence_score=95 if confirmed else 70,
        evidence=(
            f"parameter={param_name} url={page_url} payload={payload} {summary}"
        )[:500],
        dedupe_key=f"{page_url}:{param_name}:time-based-sqli",
        response_snippet=_snippet(getattr(attack, "body", None)),
        request_url=page_url,
        http_method="GET",
        tested_parameter=param_name,
        payload_used=payload,
        payload=payload,
        evidence_type="time_based",
        baseline_status_code=getattr(baseline, "status_code", None),
        attack_status_code=getattr(attack, "status_code", None),
        baseline_response_size=len(getattr(baseline, "body", "") or ""),
        attack_response_size=len(getattr(attack, "body", "") or ""),
        baseline_response_time_ms=baseline_time,
        attack_response_time_ms=attack_time,
        response_diff_summary=summary,
        false_positive_notes=(
            None
            if confirmed
            else "Timing anomaly requires manual verification; transient latency can cause false positives."
        ),
    )


async def _check_time_based_sqli(http_client, page_url: str, param_name: str, baseline):
    suspicious_issue = None
    for payload in SQLI_TIME_PAYLOADS:
        attack_url = build_sqli_probe_url(page_url, param_name, payload)
        attack = await http_client.get(attack_url)
        if not _is_time_delay(baseline, attack):
            continue

        confirmation = await http_client.get(attack_url)
        if _is_time_delay(baseline, confirmation):
            slower = confirmation if _response_time(confirmation) >= _response_time(attack) else attack
            return _issue_from_timing(
                page_url,
                param_name,
                payload,
                baseline,
                slower,
                confirmed=True,
            )

        suspicious_issue = _issue_from_timing(
            page_url,
            param_name,
            payload,
            baseline,
            attack,
            confirmed=False,
        )
        break

    return suspicious_issue


def _issue_from_diff(
    page_url: str,
    param_name: str,
    payload: str,
    baseline,
    test,
    diff: dict,
    sql_error_detected: bool,
    true_false_diff: dict | None = None,
) -> SqliIssue | None:
    signal = diff.get("confidence_signal")
    behavioral_signal = "none"
    behavioral_reason = ""
    if true_false_diff is not None:
        behavioral_signal, behavioral_reason = _behavioral_signal(diff, true_false_diff)

    strongest_signal = max(
        (signal, behavioral_signal),
        key=_signal_rank,
    )
    if strongest_signal not in {"strong", "medium", "weak"} and not sql_error_detected:
        return None

    if strongest_signal == "strong":
        severity = "high"
        confidence = "high"
        confidence_level = "confirmed"
    elif sql_error_detected:
        severity = "high"
        confidence = "high"
        confidence_level = "high"
    elif strongest_signal == "medium":
        severity = "medium"
        confidence = "medium"
        confidence_level = "medium"
    else:
        severity = "medium"
        confidence = "low"
        confidence_level = "low"

    summary = f"signal={strongest_signal}; baseline_true=({diff.get('summary', '')})"
    if true_false_diff is not None:
        summary = (
            f"{summary}; true_false=({true_false_diff.get('summary', '')}); "
            f"behavioral_reason={behavioral_reason}"
        )
    if sql_error_detected:
        summary = f"{summary}; sql_error_signature=true"

    return SqliIssue(
        category="sqli",
        title=f'Possible SQL injection via "{param_name}" parameter',
        description=(
            "A SQL injection probe produced a response anomaly or database error "
            "signature compared with the baseline response."
        ),
        severity=severity,
        remediation="Use parameterized queries and avoid exposing raw database errors.",
        confidence=confidence,
        confidence_level=confidence_level,
        evidence=(
            f"parameter={param_name} url={page_url} payload={payload} "
            f"signal={strongest_signal} summary={summary}"
        )[:500],
        dedupe_key=f"{page_url}:{param_name}:sqli",
        response_snippet=_snippet(getattr(test, "body", None)),
        request_url=page_url,
        http_method="GET",
        tested_parameter=param_name,
        payload_used=payload,
        payload=payload,
        evidence_type="behavioral",
        baseline_status_code=getattr(baseline, "status_code", None),
        attack_status_code=getattr(test, "status_code", None),
        baseline_response_size=len(getattr(baseline, "body", "") or ""),
        attack_response_size=len(getattr(test, "body", "") or ""),
        baseline_response_time_ms=getattr(baseline, "response_time_ms", None),
        attack_response_time_ms=getattr(test, "response_time_ms", None),
        response_diff_summary=summary,
    )


async def check_sqli(http_client, page_url: str, parameters: list[str]) -> list[SqliIssue]:
    issues: list[SqliIssue] = []
    for param_name in parameters:
        baseline = await http_client.get(page_url)
        timing_issue = await _check_time_based_sqli(
            http_client, page_url, param_name, baseline
        )
        if timing_issue is not None and timing_issue.confidence_level == "confirmed":
            issues.append(timing_issue)
            continue

        true_url = build_sqli_probe_url(page_url, param_name, SQLI_TRUE_PAYLOAD)
        false_url = build_sqli_probe_url(page_url, param_name, SQLI_FALSE_PAYLOAD)
        true_response = await http_client.get(true_url)
        false_response = await http_client.get(false_url)
        diff = compare_responses(baseline, true_response)
        true_false_diff = compare_responses(true_response, false_response)
        sql_error_detected = _has_sql_error(
            getattr(true_response, "body", None)
        ) or _has_sql_error(getattr(false_response, "body", None))
        issue = _issue_from_diff(
            page_url,
            param_name,
            f"{SQLI_TRUE_PAYLOAD} | {SQLI_FALSE_PAYLOAD}",
            baseline,
            true_response,
            diff,
            sql_error_detected,
            true_false_diff,
        )
        if issue is not None:
            issues.append(issue)
        elif timing_issue is not None:
            issues.append(timing_issue)
    return issues
