from dataclasses import dataclass
from typing import Mapping


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
        issues.append(
            InfoDisclosureIssue(
                category="information_disclosure",
                title="Exposed server banner",
                description="The response exposes a Server header that may reveal implementation details.",
                severity="low",
                remediation="Remove or minimize the Server header returned by the application stack.",
                confidence="high",
                evidence=server,
                dedupe_key=f"{page_url}:server-banner",
            )
        )

    powered_by = normalized_headers.get("x-powered-by")
    if powered_by:
        issues.append(
            InfoDisclosureIssue(
                category="information_disclosure",
                title="Exposed X-Powered-By header",
                description="The response exposes an X-Powered-By header that may reveal framework or runtime details.",
                severity="low",
                remediation="Disable or remove the X-Powered-By header.",
                confidence="high",
                evidence=powered_by,
                dedupe_key=f"{page_url}:x-powered-by",
            )
        )

    return issues


def check_debug_exposure(
    page_url: str, page_title: str | None, body_excerpt: str | None
) -> list[InfoDisclosureIssue]:
    haystack = " ".join(filter(None, [page_title, body_excerpt])).lower()

    if any(pattern in haystack for pattern in DEBUG_PATTERNS):
        return [
            InfoDisclosureIssue(
                category="debug_exposure",
                title="Possible debug page exposure",
                description="The response appears to include debug or exception details.",
                severity="medium",
                remediation="Disable debug mode in production and replace stack traces with generic error pages.",
                confidence="medium",
                evidence=(page_title or body_excerpt or "")[:240],
                dedupe_key=f"{page_url}:debug-exposure",
            )
        ]

    return []


def check_directory_listing(
    page_url: str, page_title: str | None, body_excerpt: str | None
) -> list[InfoDisclosureIssue]:
    haystack = " ".join(filter(None, [page_title, body_excerpt])).lower()

    if any(pattern in haystack for pattern in DIRECTORY_LISTING_PATTERNS):
        return [
            InfoDisclosureIssue(
                category="information_disclosure",
                title="Possible directory listing exposure",
                description="The response appears to expose a directory listing.",
                severity="medium",
                remediation="Disable directory listing on the web server and restrict direct browsing of file directories.",
                confidence="medium",
                evidence=(page_title or body_excerpt or "")[:240],
                dedupe_key=f"{page_url}:directory-listing",
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
        return [
            InfoDisclosureIssue(
                category="sensitive_file_exposure",
                title="Exposed .git metadata",
                description="The /.git/HEAD file is publicly accessible and exposes repository metadata.",
                severity="high",
                remediation="Block public access to the .git directory at the web server or reverse proxy layer.",
                confidence="high",
                evidence=normalized_body[:240],
                dedupe_key="sensitive:/.git/HEAD",
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
            return [
                InfoDisclosureIssue(
                    category="sensitive_file_exposure",
                    title="Exposed .env file",
                    description="The /.env file is publicly accessible and may expose sensitive configuration secrets.",
                    severity="critical",
                    remediation="Block access to .env files and ensure secrets are never exposed by the web server.",
                    confidence="high",
                    evidence=normalized_body[:240],
                    dedupe_key="sensitive:/.env",
                )
            ]

    return []
