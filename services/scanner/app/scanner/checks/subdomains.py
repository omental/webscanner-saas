import re
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Mapping
from urllib.parse import urljoin, urlsplit


@dataclass(frozen=True)
class SubdomainIssue:
    category: str
    title: str
    description: str
    severity: str
    remediation: str
    confidence: str | None
    evidence: str | None
    dedupe_key: str


@dataclass(frozen=True)
class SubdomainCandidate:
    hostname: str
    source_page_url: str
    source_type: str
    sample: str
    confidence: str


COMMON_TWO_PART_SUFFIXES = {
    "ac.uk",
    "co.jp",
    "co.uk",
    "com.au",
    "com.br",
    "com.cn",
    "com.mx",
    "com.tr",
    "com.tw",
    "co.nz",
    "co.in",
    "edu.au",
    "gov.uk",
    "net.au",
    "org.au",
    "org.uk",
}

URL_PATTERN = re.compile(r"""https?://[^\s"'<>),;]+""", re.IGNORECASE)
COOKIE_DOMAIN_PATTERN = re.compile(
    r"(?:^|;)\s*domain=(?P<domain>\.?[A-Za-z0-9.-]+)", re.IGNORECASE
)
CSP_HOST_PATTERN = re.compile(
    r"(?:(?:https?:)?//)?(?P<host>[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)(?::\d+)?",
    re.IGNORECASE,
)


class _SubdomainHtmlParser(HTMLParser):
    def __init__(self, page_url: str) -> None:
        super().__init__()
        self.page_url = page_url
        self.urls: list[tuple[str, str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_map = {key.lower(): value for key, value in attrs if value}
        tag_name = tag.lower()

        if tag_name == "a" and attrs_map.get("href"):
            self._append(attrs_map["href"], "link", "high")
        elif tag_name == "form" and attrs_map.get("action"):
            self._append(attrs_map["action"], "link", "high")
        elif tag_name == "link" and attrs_map.get("href"):
            rel = (attrs_map.get("rel") or "").lower()
            if rel == "canonical":
                self._append(attrs_map["href"], "canonical", "high")
            else:
                self._append(attrs_map["href"], "link", "medium")
        elif tag_name in {"script", "img", "iframe", "source", "video", "audio"}:
            for attr_name in ("src", "poster"):
                if attrs_map.get(attr_name):
                    self._append(attrs_map[attr_name], "link", "medium")

    def _append(self, value: str, source_type: str, confidence: str) -> None:
        self.urls.append((urljoin(self.page_url, value), source_type, confidence))


def discover_subdomains_from_page(
    target_url: str,
    page_url: str,
    html_content: str | None,
    headers: Mapping[str, str] | None,
    *,
    max_results: int = 100,
) -> list[SubdomainIssue]:
    target_host = _hostname(target_url)
    registered_domain = registered_domain_for_host(target_host)
    if not target_host or not registered_domain:
        return []

    candidates: list[SubdomainCandidate] = []
    candidates.extend(_extract_from_html(registered_domain, target_host, page_url, html_content))
    candidates.extend(_extract_from_headers(registered_domain, target_host, page_url, headers or {}))

    issues: list[SubdomainIssue] = []
    seen_hosts: set[str] = set()
    for candidate in candidates:
        if candidate.hostname in seen_hosts:
            continue
        seen_hosts.add(candidate.hostname)
        issues.append(_issue_from_candidate(candidate))
        if len(issues) >= max_results:
            break

    return issues


def registered_domain_for_host(hostname: str | None) -> str | None:
    if not hostname:
        return None
    labels = [label for label in hostname.lower().strip(".").split(".") if label]
    if len(labels) < 2:
        return None
    suffix = ".".join(labels[-2:])
    if len(labels) >= 3 and suffix in COMMON_TWO_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return suffix


def _extract_from_html(
    registered_domain: str,
    target_host: str,
    page_url: str,
    html_content: str | None,
) -> list[SubdomainCandidate]:
    if not html_content:
        return []

    parser = _SubdomainHtmlParser(page_url)
    parser.feed(html_content)

    candidates: list[SubdomainCandidate] = []
    for sample_url, source_type, confidence in parser.urls:
        host = _normalize_candidate_host(sample_url, registered_domain, target_host)
        if host:
            candidates.append(
                SubdomainCandidate(
                    hostname=host,
                    source_page_url=page_url,
                    source_type=source_type,
                    sample=sample_url,
                    confidence=confidence,
                )
            )
    return candidates


def _extract_from_headers(
    registered_domain: str,
    target_host: str,
    page_url: str,
    headers: Mapping[str, str],
) -> list[SubdomainCandidate]:
    normalized_headers = {key.lower(): value for key, value in headers.items()}
    candidates: list[SubdomainCandidate] = []

    for header_name in ("location", "link"):
        value = normalized_headers.get(header_name)
        if not value:
            continue
        for url in URL_PATTERN.findall(value):
            host = _normalize_candidate_host(url, registered_domain, target_host)
            if host:
                candidates.append(
                    SubdomainCandidate(host, page_url, "header", value, "high")
                )

    csp = normalized_headers.get("content-security-policy")
    if csp:
        for match in CSP_HOST_PATTERN.finditer(csp):
            host = _host_if_related_subdomain(
                match.group("host"), registered_domain, target_host
            )
            if host:
                candidates.append(SubdomainCandidate(host, page_url, "csp", csp, "high"))

    set_cookie = normalized_headers.get("set-cookie")
    if set_cookie:
        for match in COOKIE_DOMAIN_PATTERN.finditer(set_cookie):
            host = _host_if_related_subdomain(
                match.group("domain"), registered_domain, target_host
            )
            if host:
                candidates.append(
                    SubdomainCandidate(host, page_url, "cookie", match.group(0), "high")
                )

    return candidates


def _normalize_candidate_host(
    value: str, registered_domain: str, target_host: str
) -> str | None:
    return _host_if_related_subdomain(_hostname(value), registered_domain, target_host)


def _host_if_related_subdomain(
    hostname: str | None, registered_domain: str, target_host: str
) -> str | None:
    if not hostname:
        return None
    host = hostname.lower().strip(".")
    if host == target_host:
        return None
    if host == registered_domain:
        return None
    if not host.endswith(f".{registered_domain}"):
        return None
    return host


def _hostname(url_or_host: str | None) -> str | None:
    if not url_or_host:
        return None
    value = url_or_host.strip()
    parsed = urlsplit(value if "://" in value else f"//{value}")
    return (parsed.hostname or "").lower().strip(".") or None


def _issue_from_candidate(candidate: SubdomainCandidate) -> SubdomainIssue:
    evidence = (
        f"subdomain={candidate.hostname} source_page={candidate.source_page_url} "
        f"source_type={candidate.source_type} sample={_shorten(candidate.sample)}"
    )
    return SubdomainIssue(
        category="subdomain_discovery",
        title="Discovered related subdomain",
        description="A related subdomain was passively observed in crawled content or response metadata.",
        severity="informational",
        remediation=(
            "Review this passive asset signal before deciding whether to add the "
            "subdomain as a separate scan target."
        ),
        confidence=candidate.confidence,
        evidence=evidence[:500],
        dedupe_key=f"subdomain:{candidate.hostname}",
    )


def _shorten(value: str, limit: int = 220) -> str:
    return re.sub(r"\s+", " ", value).strip()[:limit]
