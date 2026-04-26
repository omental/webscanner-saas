from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urlsplit


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
            issues.append(
                HeaderIssue(
                    category="missing_security_header",
                    title=title,
                    description=description,
                    severity=severity,
                    remediation=remediation,
                    confidence="high",
                    evidence=header_name,
                    dedupe_key=f"{page_url}:{header_name}",
                )
            )

    if urlsplit(page_url).scheme == "https" and "strict-transport-security" not in normalized_headers:
        issues.append(
            HeaderIssue(
                category="missing_security_header",
                title="Missing Strict-Transport-Security",
                description="The HTTPS response does not include a Strict-Transport-Security header.",
                severity="medium",
                remediation="Enable HSTS for HTTPS responses.",
                confidence="high",
                evidence="strict-transport-security",
                dedupe_key=f"{page_url}:strict-transport-security",
            )
        )

    return issues
