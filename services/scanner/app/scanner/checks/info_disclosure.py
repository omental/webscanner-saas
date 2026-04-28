from dataclasses import dataclass
from typing import Mapping

from app.services.confidence import finding_confidence_metadata


@dataclass(frozen=True)
class InfoDisclosureIssue:
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


DEBUG_PATTERNS = (
    "traceback (most recent call last)",
    "stack trace",
    "exception occurred",
    "debug mode",
    "phpinfo()",
    "php version",
    "fatal error:",
    "uncaught exception",
)

DIRECTORY_LISTING_PATTERNS = (
    "index of /",
    "<title>index of /",
    "<h1>index of /",
    "directory listing for /",
)


def _normalize_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {key.lower(): value for key, value in headers.items()}


def check_banner_exposure(
    page_url: str, headers: Mapping[str, str]
) -> list[InfoDisclosureIssue]:
    normalized_headers = _normalize_headers(headers)
    issues: list[InfoDisclosureIssue] = []

    server = normalized_headers.get("server")
    if server:
        metadata = finding_confidence_metadata(
            informational=True,
            response_snippet=server[:240],
            verification_steps=["Confirm the Server header is present in the response."],
            request_url=page_url,
            http_method="GET",
            response_diff_summary="response_header=server",
            false_positive_notes="Server banners can be generic or injected by upstream infrastructure.",
        )
        issues.append(
            InfoDisclosureIssue(
                category="information_disclosure",
                title="Exposed server banner",
                description="The response exposes a Server header that may reveal implementation details.",
                severity="low",
                remediation="Remove or minimize the Server header returned by the application stack.",
                confidence=str(metadata["confidence_level"]),
                evidence=server,
                dedupe_key=f"{page_url}:server-banner",
                **metadata,
            )
        )

    powered_by = normalized_headers.get("x-powered-by")
    if powered_by:
        metadata = finding_confidence_metadata(
            informational=True,
            response_snippet=powered_by[:240],
            verification_steps=["Confirm the X-Powered-By header is present in the response."],
            request_url=page_url,
            http_method="GET",
            response_diff_summary="response_header=x-powered-by",
            false_positive_notes="Framework headers can be added by middleware or upstream services.",
        )
        issues.append(
            InfoDisclosureIssue(
                category="information_disclosure",
                title="Exposed X-Powered-By header",
                description="The response exposes an X-Powered-By header that may reveal framework or runtime details.",
                severity="low",
                remediation="Disable or remove the X-Powered-By header.",
                confidence=str(metadata["confidence_level"]),
                evidence=powered_by,
                dedupe_key=f"{page_url}:x-powered-by",
                **metadata,
            )
        )

    return issues


def check_debug_exposure(
    page_url: str, page_title: str | None, body_excerpt: str | None
) -> list[InfoDisclosureIssue]:
    haystack = " ".join(filter(None, [page_title, body_excerpt])).lower()

    if any(pattern in haystack for pattern in DEBUG_PATTERNS):
        snippet = (page_title or body_excerpt or "")[:240]
        metadata = finding_confidence_metadata(
            known_error_signature=True,
            response_snippet=snippet,
            request_url=page_url,
            http_method="GET",
            attack_response_size=len(body_excerpt) if body_excerpt is not None else None,
            response_diff_summary="matched_debug_or_exception_pattern",
            verification_steps=[
                "Review the matched page content for stack traces or debug output.",
                "Confirm the response is reachable without authentication.",
            ],
        )
        return [
            InfoDisclosureIssue(
                category="debug_exposure",
                title="Possible debug page exposure",
                description="The response appears to include debug or exception details.",
                severity="medium",
                remediation="Disable debug mode in production and replace stack traces with generic error pages.",
                confidence=str(metadata["confidence_level"]),
                evidence=snippet,
                dedupe_key=f"{page_url}:debug-exposure",
                **metadata,
            )
        ]

    return []


def check_directory_listing(
    page_url: str, page_title: str | None, body_excerpt: str | None
) -> list[InfoDisclosureIssue]:
    haystack = " ".join(filter(None, [page_title, body_excerpt])).lower()

    if any(pattern in haystack for pattern in DIRECTORY_LISTING_PATTERNS):
        snippet = (page_title or body_excerpt or "")[:240]
        metadata = finding_confidence_metadata(
            weak_signal_count=2,
            response_snippet=snippet,
            request_url=page_url,
            http_method="GET",
            attack_response_size=len(body_excerpt) if body_excerpt is not None else None,
            response_diff_summary="matched_directory_listing_pattern",
            verification_steps=[
                "Open the URL and confirm a directory index is visible.",
                "Check whether the listing exposes non-public files.",
            ],
            false_positive_notes="Some intentionally public file indexes may be acceptable.",
        )
        return [
            InfoDisclosureIssue(
                category="information_disclosure",
                title="Possible directory listing exposure",
                description="The response appears to expose a directory listing.",
                severity="medium",
                remediation="Disable directory listing on the web server and restrict direct browsing of file directories.",
                confidence=str(metadata["confidence_level"]),
                evidence=snippet,
                dedupe_key=f"{page_url}:directory-listing",
                **metadata,
            )
        ]

    return []


def classify_sensitive_file_exposure(
    path: str,
    status_code: int | None,
    body: str | None,
    content_type: str | None,
) -> list[InfoDisclosureIssue]:
    if status_code != 200 or not body:
        return []

    normalized_body = body.strip()
    body_lower = normalized_body.lower()
    content_type_lower = (content_type or "").lower()

    if path == "/.git/HEAD" and normalized_body.startswith("ref:"):
        snippet = normalized_body[:240]
        metadata = finding_confidence_metadata(
            context_validated=True,
            payload_reflected=True,
            response_snippet=snippet,
            request_url=path,
            http_method="GET",
            attack_status_code=status_code,
            attack_response_size=len(body) if body is not None else None,
            response_diff_summary="path=/.git/HEAD; matched_git_ref",
            verification_steps=[
                "Request /.git/HEAD and confirm it returns a Git ref.",
                "Block access to /.git/* and verify the file is no longer accessible.",
            ],
        )
        return [
            InfoDisclosureIssue(
                category="sensitive_file_exposure",
                title="Exposed .git metadata",
                description="The /.git/HEAD file is publicly accessible and exposes repository metadata.",
                severity="high",
                remediation="Block public access to the .git directory at the web server or reverse proxy layer.",
                confidence=str(metadata["confidence_level"]),
                evidence=snippet,
                dedupe_key="sensitive:/.git/HEAD",
                **metadata,
            )
        ]

    if path == "/.env":
        looks_like_env = (
            "database_url=" in body_lower
            or "app_key=" in body_lower
            or "secret_key=" in body_lower
            or "api_key=" in body_lower
            or ("\n" in normalized_body and "=" in normalized_body)
        )
        if looks_like_env and ("text" in content_type_lower or not content_type_lower):
            snippet = normalized_body[:240]
            metadata = finding_confidence_metadata(
                exploit_confirmed=True,
                response_snippet=snippet,
                request_url=path,
                http_method="GET",
                attack_status_code=status_code,
                attack_response_size=len(body) if body is not None else None,
                response_diff_summary="path=/.env; matched_env_key_value_content",
                verification_steps=[
                    "Request /.env and confirm key-value secret material is returned.",
                    "Rotate any exposed secrets and block access to dotenv files.",
                ],
            )
            return [
                InfoDisclosureIssue(
                    category="sensitive_file_exposure",
                    title="Exposed .env file",
                    description="The /.env file is publicly accessible and may expose sensitive configuration secrets.",
                    severity="critical",
                    remediation="Block access to .env files and ensure secrets are never exposed by the web server.",
                    confidence=str(metadata["confidence_level"]),
                    evidence=snippet,
                    dedupe_key="sensitive:/.env",
                    **metadata,
                )
            ]

    return []
