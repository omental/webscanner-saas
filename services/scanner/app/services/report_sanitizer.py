"""Sanitize scan data into a safe dict suitable for LLM report generation.

Every value that could leak credentials, tokens, raw payloads, or full
request/response content is masked or stripped before the dict is returned.
The resulting structure contains only the minimum information the LLM
needs to write an accurate vulnerability report.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any


# ---------------------------------------------------------------------------
# Sensitive-text masking
# ---------------------------------------------------------------------------

# Order matters: more specific patterns first, catch-all at the end.
_SENSITIVE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Authorization / Bearer / tokens in header-like lines
    (
        re.compile(
            r"(Authorization\s*[:=]\s*)(Bearer\s+)?\S+",
            re.IGNORECASE,
        ),
        r"\1[REDACTED]",
    ),
    # Standalone Bearer token values
    (
        re.compile(r"Bearer\s+[A-Za-z0-9\-_\.]{8,}", re.IGNORECASE),
        "Bearer [REDACTED]",
    ),
    # JWT-like tokens  (three base64url segments separated by dots)
    (
        re.compile(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"),
        "[REDACTED_JWT]",
    ),
    # API key patterns  (common prefixes or generic "key=…" pairs)
    (
        re.compile(
            r"(api[_-]?key|apikey|x-api-key)\s*[:=]\s*\S+",
            re.IGNORECASE,
        ),
        r"\1=[REDACTED]",
    ),
    # sk-… / pk-… style keys (OpenAI, Stripe, etc.)
    (
        re.compile(r"\b(sk|pk|rk)[-_][A-Za-z0-9\-_]{16,}\b"),
        "[REDACTED_KEY]",
    ),
    # Cookie header values
    (
        re.compile(r"(Cookie\s*[:=]\s*)(.+)", re.IGNORECASE),
        r"\1[REDACTED]",
    ),
    # Set-Cookie header values
    (
        re.compile(r"(Set-Cookie\s*[:=]\s*)(.+)", re.IGNORECASE),
        r"\1[REDACTED]",
    ),
    # Session IDs (common naming)
    (
        re.compile(
            r"(session[_-]?id|sessionid|PHPSESSID|JSESSIONID|ASP\.NET_SessionId|"
            r"connect\.sid|_session)\s*[=:]\s*\S+",
            re.IGNORECASE,
        ),
        r"\1=[REDACTED]",
    ),
    # Password / secret / private-key fields
    (
        re.compile(
            r"(password|passwd|secret|private[_-]?key|access[_-]?token|"
            r"refresh[_-]?token)\s*[=:]\s*\S+",
            re.IGNORECASE,
        ),
        r"\1=[REDACTED]",
    ),
    # Raw HTTP request / response blocks  (anything that looks like
    # a full HTTP message: "GET /… HTTP/1.1\r\n…" or "HTTP/1.1 200 …")
    (
        re.compile(
            r"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+\s+HTTP/[\d.]+.*?"
            r"(?:\r?\n\r?\n)",
            re.DOTALL | re.IGNORECASE,
        ),
        "[REDACTED_RAW_REQUEST]",
    ),
    (
        re.compile(
            r"HTTP/[\d.]+\s+\d{3}.*?(?:\r?\n\r?\n)",
            re.DOTALL | re.IGNORECASE,
        ),
        "[REDACTED_RAW_RESPONSE]",
    ),
]


def mask_sensitive_text(value: str) -> str:
    """Return *value* with credentials, tokens, and raw payloads masked.

    The function applies a curated set of regex substitutions designed to
    remove common secret patterns while preserving enough surrounding context
    for an LLM to reference the finding in a report.
    """
    if not value:
        return value

    result = value
    for pattern, replacement in _SENSITIVE_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


# ---------------------------------------------------------------------------
# Safe-value helpers
# ---------------------------------------------------------------------------

def _safe_str(value: Any) -> str | None:
    """Convert to string and mask, or return None for falsy values."""
    if value is None:
        return None
    text = str(value)
    if not text.strip():
        return None
    return mask_sensitive_text(text)


def _safe_dt(value: Any) -> str | None:
    """Return an ISO-8601 string or None."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _getattr_safe(obj: Any, name: str, default: Any = None) -> Any:
    """Read an attribute without crashing if *obj* is a dict or missing it."""
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _safe_list(value: Any) -> list[Any] | None:
    if value is None:
        return None
    if isinstance(value, list):
        return [_safe_str(item) for item in value if _safe_str(item) is not None]
    return [_safe_str(value)]


def _confidence_group(confidence_level: Any) -> str:
    normalized = str(confidence_level or "").lower()
    if normalized in {"confirmed", "high", "medium"}:
        return "main_security_findings"
    return "informational_observations"


# ---------------------------------------------------------------------------
# Main sanitizer
# ---------------------------------------------------------------------------

def build_sanitized_scan_report_data(
    scan: Any,
    target: Any,
    findings: list[Any] | None,
    pages: list[Any] | None = None,
    technologies: list[Any] | None = None,
) -> dict:
    """Return a dict containing only LLM-safe report data.

    Accepts SQLAlchemy model instances **or** plain dicts — whichever the
    caller happens to have.  Missing / ``None`` collections are treated as
    empty lists so the function never crashes on absent data.
    """
    findings = findings or []
    pages = pages or []
    technologies = technologies or []

    # --- scan ----------------------------------------------------------
    scan_data: dict[str, Any] = {
        "id": _getattr_safe(scan, "id"),
        "status": _getattr_safe(scan, "status"),
        "scan_type": _getattr_safe(scan, "scan_type"),
        "scan_profile": _getattr_safe(scan, "scan_profile") or "standard",
        "previous_scan_id": _getattr_safe(scan, "previous_scan_id"),
        "comparison_summary": _getattr_safe(scan, "comparison_summary"),
        "total_pages_found": _getattr_safe(scan, "total_pages_found"),
        "total_findings": _getattr_safe(scan, "total_findings"),
        "risk_score": _getattr_safe(scan, "risk_score"),
        "created_at": _safe_dt(_getattr_safe(scan, "created_at")),
        "started_at": _safe_dt(_getattr_safe(scan, "started_at")),
        "finished_at": _safe_dt(_getattr_safe(scan, "finished_at")),
    }

    # --- target --------------------------------------------------------
    target_data: dict[str, Any] = {
        "id": _getattr_safe(target, "id"),
        "base_url": _getattr_safe(target, "base_url"),
        "normalized_domain": _getattr_safe(target, "normalized_domain"),
    }

    # --- pages (URL & path only — no headers, no body) -----------------
    safe_pages: list[dict[str, Any]] = []
    for page in pages:
        safe_pages.append(
            {
                "url": _getattr_safe(page, "url"),
                "status_code": _getattr_safe(page, "status_code"),
                "content_type": _getattr_safe(page, "content_type"),
                "depth": _getattr_safe(page, "depth"),
            }
        )

    # --- technologies (name / version / category only) -----------------
    safe_techs: list[dict[str, Any]] = []
    for tech in technologies:
        safe_techs.append(
            {
                "product_name": _getattr_safe(tech, "product_name"),
                "category": _getattr_safe(tech, "category"),
                "version": _getattr_safe(tech, "version"),
                "vendor": _getattr_safe(tech, "vendor"),
            }
        )

    # --- findings ------------------------------------------------------
    safe_findings: list[dict[str, Any]] = []
    for finding in findings:
        confidence_level = _getattr_safe(finding, "confidence_level")
        item = {
            "id": _getattr_safe(finding, "id"),
            "title": _getattr_safe(finding, "title"),
            "severity": _getattr_safe(finding, "severity"),
            "category": _getattr_safe(finding, "category"),
            "confidence": _getattr_safe(finding, "confidence"),
            "confidence_level": confidence_level,
            "confidence_score": _getattr_safe(finding, "confidence_score"),
            "evidence_type": _safe_str(_getattr_safe(finding, "evidence_type")),
            "verification_steps": _safe_list(
                _getattr_safe(finding, "verification_steps")
            ),
            "payload_used": _safe_str(_getattr_safe(finding, "payload_used")),
            "affected_parameter": _safe_str(
                _getattr_safe(finding, "affected_parameter")
            ),
            "response_snippet": _safe_str(_getattr_safe(finding, "response_snippet")),
            "false_positive_notes": _safe_str(
                _getattr_safe(finding, "false_positive_notes")
            ),
            "request_url": _safe_str(_getattr_safe(finding, "request_url")),
            "http_method": _safe_str(_getattr_safe(finding, "http_method")),
            "tested_parameter": _safe_str(_getattr_safe(finding, "tested_parameter")),
            "payload": _safe_str(_getattr_safe(finding, "payload")),
            "baseline_status_code": _getattr_safe(finding, "baseline_status_code"),
            "attack_status_code": _getattr_safe(finding, "attack_status_code"),
            "baseline_response_size": _getattr_safe(finding, "baseline_response_size"),
            "attack_response_size": _getattr_safe(finding, "attack_response_size"),
            "baseline_response_time_ms": _getattr_safe(
                finding, "baseline_response_time_ms"
            ),
            "attack_response_time_ms": _getattr_safe(
                finding, "attack_response_time_ms"
            ),
            "response_diff_summary": _safe_str(
                _getattr_safe(finding, "response_diff_summary")
            ),
            "deduplication_key": _safe_str(_getattr_safe(finding, "deduplication_key")),
            "comparison_status": _safe_str(
                _getattr_safe(finding, "comparison_status")
            ),
            "confidence_group": _confidence_group(confidence_level),
            "description": _safe_str(_getattr_safe(finding, "description")),
            "evidence": _safe_str(_getattr_safe(finding, "evidence")),
            "remediation": _safe_str(_getattr_safe(finding, "remediation")),
            "created_at": _safe_dt(_getattr_safe(finding, "created_at")),
        }
        safe_findings.append(item)

    main_security_findings = [
        finding
        for finding in safe_findings
        if finding["confidence_group"] == "main_security_findings"
    ]
    informational_observations = [
        finding
        for finding in safe_findings
        if finding["confidence_group"] == "informational_observations"
    ]

    return {
        "scan": scan_data,
        "target": target_data,
        "pages": safe_pages,
        "technologies": safe_techs,
        "findings": safe_findings,
        "finding_groups": {
            "main_security_findings": main_security_findings,
            "informational_observations": informational_observations,
        },
    }
