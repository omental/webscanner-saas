from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit


@dataclass(frozen=True)
class CrawlIssue:
    category: str
    title: str
    description: str
    severity: str
    remediation: str
    confidence: str | None
    evidence: str | None
    dedupe_key: str


def _headers(page: object) -> dict[str, str]:
    raw_headers = getattr(page, "response_headers", None) or {}
    return {key.lower(): value for key, value in raw_headers.items()}


def _canonical_url(url: str) -> str:
    parts = urlsplit(url)
    return parts._replace(fragment="").geturl()


def _location_url(page: object) -> str | None:
    location = _headers(page).get("location")
    if not location:
        return None
    return _canonical_url(urljoin(getattr(page, "url"), location))


def check_crawl_page(page: object) -> list[CrawlIssue]:
    status_code = getattr(page, "status_code", None)
    page_url = getattr(page, "url")

    if status_code == 404:
        return [
            CrawlIssue(
                category="crawl_issue",
                title="Page returns 404",
                description="A crawled internal URL returned a 404 Not Found response.",
                severity="low",
                remediation="Update or remove internal links that point to this URL.",
                confidence="high",
                evidence=f"url={page_url}",
                dedupe_key=f"{page_url}:404",
            )
        ]

    if status_code in {301, 302}:
        location = _location_url(page)
        return [
            CrawlIssue(
                category="crawl_issue",
                title="Redirect page",
                description="A crawled internal URL returned a redirect response.",
                severity="info",
                remediation="Review internal links and link directly to the final destination when appropriate.",
                confidence="high",
                evidence=f"url={page_url} status={status_code} location={location or '-'}",
                dedupe_key=f"{page_url}:redirect",
            )
        ]

    return []


def check_redirect_chains(pages: list[object]) -> list[CrawlIssue]:
    pages_by_url = {_canonical_url(getattr(page, "url")): page for page in pages}
    issues: list[CrawlIssue] = []

    for page in pages:
        if getattr(page, "status_code", None) not in {301, 302}:
            continue

        chain = [_canonical_url(getattr(page, "url"))]
        seen = set(chain)
        next_url = _location_url(page)

        while next_url and next_url in pages_by_url and next_url not in seen:
            chain.append(next_url)
            seen.add(next_url)
            next_page = pages_by_url[next_url]
            if getattr(next_page, "status_code", None) not in {301, 302}:
                break
            next_url = _location_url(next_page)

        redirect_hops = max(len(chain) - 1, 0)
        if redirect_hops > 1:
            issues.append(
                CrawlIssue(
                    category="crawl_issue",
                    title="Redirect chain detected",
                    description="A crawled internal URL redirects through more than one hop.",
                    severity="low",
                    remediation="Point internal links to the final destination URL.",
                    confidence="medium",
                    evidence=f"chain={' -> '.join(chain[:4])}",
                    dedupe_key=f"{chain[0]}:redirect-chain",
                )
            )

    return issues


def summarize_crawl_issues(pages: list[object]) -> list[CrawlIssue]:
    not_found_count = sum(1 for page in pages if getattr(page, "status_code", None) == 404)
    redirect_count = sum(
        1 for page in pages if getattr(page, "status_code", None) in {301, 302}
    )
    dead_internal_link_count = sum(
        1
        for page in pages
        if getattr(page, "status_code", None) == 404
        and getattr(page, "discovered_from", None)
    )
    redirect_chain_count = len(check_redirect_chains(pages))

    if (
        not_found_count == 0
        and redirect_count == 0
        and dead_internal_link_count == 0
        and redirect_chain_count == 0
    ):
        return []

    return [
        CrawlIssue(
            category="crawl_issue",
            title="Crawl issue summary",
            description="The crawl found broken pages, redirects, or redirect chains.",
            severity="info",
            remediation="Review crawl issues and update internal links where needed.",
            confidence="high",
            evidence=(
                f"404_pages={not_found_count} redirects={redirect_count} "
                f"dead_internal_links={dead_internal_link_count} "
                f"redirect_chains={redirect_chain_count}"
            ),
            dedupe_key="crawl-issue-summary",
        )
    ]
