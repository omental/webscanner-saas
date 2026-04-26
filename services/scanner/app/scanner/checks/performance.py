from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class PerformanceIssue:
    category: str
    title: str
    description: str
    severity: str
    remediation: str
    confidence: str | None
    evidence: str | None
    dedupe_key: str


def check_performance(
    *,
    page_url: str,
    status_code: int | None,
    content_type: str | None,
    response_time_ms: int | None,
    headers: dict[str, str] | None,
) -> list[PerformanceIssue]:
    normalized_headers = {key.lower(): value for key, value in (headers or {}).items()}
    issues: list[PerformanceIssue] = []

    if response_time_ms is not None:
        if response_time_ms > 3000:
            issues.append(
                PerformanceIssue(
                    category="performance",
                    title="Very slow page response",
                    description="The page took more than 3000ms to respond.",
                    severity="high",
                    remediation="Investigate backend latency, database performance, and caching for this page.",
                    confidence="high",
                    evidence=f"{response_time_ms}ms",
                    dedupe_key=f"{page_url}:slow-response-high",
                )
            )
        elif response_time_ms > 1500:
            issues.append(
                PerformanceIssue(
                    category="performance",
                    title="Slow page response",
                    description="The page took more than 1500ms to respond.",
                    severity="medium",
                    remediation="Reduce response time with caching, query optimization, and lighter page processing.",
                    confidence="high",
                    evidence=f"{response_time_ms}ms",
                    dedupe_key=f"{page_url}:slow-response-medium",
                )
            )

    if status_code in {301, 302}:
        issues.append(
            PerformanceIssue(
                category="performance",
                title="Redirect response detected",
                description="The page responded with a redirect, which adds an extra request before content is reached.",
                severity="low",
                remediation="Link directly to the final destination URL where possible.",
                confidence="high",
                evidence=str(status_code),
                dedupe_key=f"{page_url}:redirect",
            )
        )

    normalized_content_type = _normalize_content_type(content_type)
    if normalized_content_type == "text/html":
        content_encoding = normalized_headers.get("content-encoding", "").lower()
        if not any(token in content_encoding for token in ("gzip", "br", "zstd")):
            issues.append(
                PerformanceIssue(
                    category="performance",
                    title="Missing response compression",
                    description="The HTML response does not appear to use gzip, br, or zstd compression.",
                    severity="medium",
                    remediation="Enable compression for HTML responses to reduce transfer size.",
                    confidence="medium",
                    evidence=normalized_headers.get("content-encoding") or "none",
                    dedupe_key=f"{page_url}:missing-compression",
                )
            )

    content_length = _parse_content_length(normalized_headers.get("content-length"))
    if content_length is not None:
        if normalized_content_type == "text/html" and content_length > 750_000:
            issues.append(
                PerformanceIssue(
                    category="performance",
                    title="Large HTML response",
                    description="The HTML response appears unusually large.",
                    severity="medium",
                    remediation="Reduce page size by trimming markup, scripts, and unused content.",
                    confidence="medium",
                    evidence=f"{content_length} bytes",
                    dedupe_key=f"{page_url}:large-html",
                )
            )

        if _is_static_asset(page_url, normalized_content_type):
            if content_length > 1_000_000:
                issues.append(
                    PerformanceIssue(
                        category="performance",
                        title="Large static asset",
                        description="The static asset is large and may slow down page loads.",
                        severity="medium",
                        remediation="Compress, resize, or split large assets where practical.",
                        confidence="medium",
                        evidence=f"{content_length} bytes",
                        dedupe_key=f"{page_url}:large-asset",
                    )
                )
            if "cache-control" not in normalized_headers and "expires" not in normalized_headers:
                issues.append(
                    PerformanceIssue(
                        category="performance",
                        title="Missing asset cache headers",
                        description="The static asset response does not include Cache-Control or Expires headers.",
                        severity="low",
                        remediation="Add long-lived cache headers for versioned static assets.",
                        confidence="medium",
                        evidence=normalized_content_type or urlsplit(page_url).path,
                        dedupe_key=f"{page_url}:missing-cache-headers",
                    )
                )

    return issues


def _normalize_content_type(content_type: str | None) -> str | None:
    if not content_type:
        return None
    return content_type.split(";", 1)[0].strip().lower()


def _parse_content_length(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _is_static_asset(page_url: str, content_type: str | None) -> bool:
    if content_type and (
        content_type.startswith("image/")
        or content_type in {"text/css", "application/javascript", "text/javascript"}
    ):
        return True

    path = urlsplit(page_url).path.lower()
    return path.endswith(
        (
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".webp",
            ".svg",
            ".css",
            ".js",
        )
    )
