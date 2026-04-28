from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urlsplit

from app.services.confidence import finding_confidence_metadata


@dataclass(frozen=True)
class HeaderIssue:
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


REQUIRED_HEADERS = {
    "content-security-policy": (
        "Missing Content-Security-Policy",
        "The response does not include a Content-Security-Policy header.",
        "medium",
        "Add a Content-Security-Policy header restricting trusted content sources.",
    ),
    "x-frame-options": (
        "Missing X-Frame-Options",
        "The response does not include an X-Frame-Options header.",
        "medium",
        "Set X-Frame-Options to DENY or SAMEORIGIN.",
    ),
    "x-content-type-options": (
        "Missing X-Content-Type-Options",
        "The response does not include an X-Content-Type-Options header.",
        "low",
        "Set X-Content-Type-Options to nosniff.",
    ),
    "referrer-policy": (
        "Missing Referrer-Policy",
        "The response does not include a Referrer-Policy header.",
        "low",
        "Add a Referrer-Policy appropriate for the app.",
    ),
}


def _normalize_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {key.lower(): value for key, value in headers.items()}


def check_security_headers(
    page_url: str, headers: Mapping[str, str]
) -> list[HeaderIssue]:
    normalized_headers = _normalize_headers(headers)
    issues: list[HeaderIssue] = []

    for header_name, (title, description, severity, remediation) in REQUIRED_HEADERS.items():
        if header_name not in normalized_headers:
            metadata = finding_confidence_metadata(
                weak_signal_count=2 if severity == "medium" else 1,
                verification_steps=[
                    f"Request {page_url} and confirm the {header_name} header is absent.",
                    "Check whether the header is set by an upstream proxy or CDN.",
                ],
                request_url=page_url,
                http_method="GET",
                response_diff_summary=f"missing_header={header_name}",
                false_positive_notes="Header may be intentionally omitted on non-sensitive static responses.",
            )
            issues.append(
                HeaderIssue(
                    category="missing_security_header",
                    title=title,
                    description=description,
                    severity=severity,
                    remediation=remediation,
                    confidence=str(metadata["confidence_level"]),
                    evidence=header_name,
                    dedupe_key=f"{page_url}:{header_name}",
                    **metadata,
                )
            )

    if urlsplit(page_url).scheme == "https" and "strict-transport-security" not in normalized_headers:
        metadata = finding_confidence_metadata(
            weak_signal_count=2,
            verification_steps=[
                f"Request {page_url} over HTTPS and confirm Strict-Transport-Security is absent.",
                "Confirm the response is not a local development or staging environment.",
            ],
            request_url=page_url,
            http_method="GET",
            response_diff_summary="missing_header=strict-transport-security",
            false_positive_notes="HSTS only applies to HTTPS responses and may be absent on first deployment.",
        )
        issues.append(
            HeaderIssue(
                category="missing_security_header",
                title="Missing Strict-Transport-Security",
                description="The HTTPS response does not include a Strict-Transport-Security header.",
                severity="medium",
                remediation="Enable HSTS for HTTPS responses.",
                confidence=str(metadata["confidence_level"]),
                evidence="strict-transport-security",
                dedupe_key=f"{page_url}:strict-transport-security",
                **metadata,
            )
        )

    return issues
