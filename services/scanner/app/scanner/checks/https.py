import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


@dataclass(frozen=True)
class HttpsIssue:
    category: str
    title: str
    description: str
    severity: str
    remediation: str
    confidence: str | None
    evidence: str | None
    dedupe_key: str


_HTTP_ASSET_PATTERN = re.compile(
    r"""(?:src|href)\s*=\s*["'](?P<url>http://[^"'\s>]+)["']""",
    re.IGNORECASE,
)


def https_variant(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit(("https", parts.netloc, parts.path or "", parts.query, ""))


def http_variant(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit(("http", parts.netloc, parts.path or "", parts.query, ""))


def classify_transport(
    base_url: str,
    final_url: str,
    *,
    https_available: bool | None = None,
) -> list[HttpsIssue]:
    base_scheme = urlsplit(base_url).scheme.lower()
    final_scheme = urlsplit(final_url).scheme.lower()

    if base_scheme == "http" and https_available is False:
        return [
            HttpsIssue(
                category="insecure_transport",
                title="No HTTPS available",
                description="The target is served over HTTP and an HTTPS version was not reachable.",
                severity="high",
                remediation="Enable HTTPS for the site and redirect all HTTP traffic to HTTPS.",
                confidence="high",
                evidence=f"url={base_url}",
                dedupe_key=f"{urlsplit(base_url).netloc}:no-https",
            )
        ]

    if base_scheme == "http" and final_scheme != "https":
        return [
            HttpsIssue(
                category="insecure_transport",
                title="HTTP does not redirect to HTTPS",
                description="The target started on HTTP and did not end on HTTPS.",
                severity="medium" if https_available else "high",
                remediation="Redirect all HTTP traffic to HTTPS.",
                confidence="high",
                evidence=f"url={base_url} final_url={final_url}",
                dedupe_key=f"{urlsplit(base_url).netloc}:http-no-https-redirect",
            )
        ]

    if final_scheme == "http":
        return [
            HttpsIssue(
                category="insecure_transport",
                title="Final response served over HTTP",
                description="The final response for the target was served over HTTP.",
                severity="high",
                remediation="Serve the application over HTTPS and redirect all HTTP traffic to HTTPS.",
                confidence="high",
                evidence=f"url={base_url} final_url={final_url}",
                dedupe_key=f"{urlsplit(base_url).netloc}:final-http",
            )
        ]

    return []


def check_mixed_content(page_url: str, html_content: str | None) -> list[HttpsIssue]:
    if urlsplit(page_url).scheme.lower() != "https" or not html_content:
        return []

    match = _HTTP_ASSET_PATTERN.search(html_content)
    if not match:
        return []

    sample_url = match.group("url")
    return [
        HttpsIssue(
            category="insecure_transport",
            title="Mixed content asset",
            description="An HTTPS page references an asset over plain HTTP.",
            severity="medium",
            remediation="Load scripts, styles, images, and other assets over HTTPS.",
            confidence="medium",
            evidence=f"url={page_url} sample_asset={sample_url}"[:500],
            dedupe_key=f"{urlsplit(page_url).netloc}:mixed-content",
        )
    ]
