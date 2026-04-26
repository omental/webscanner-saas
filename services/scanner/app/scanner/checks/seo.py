from dataclasses import dataclass
from html.parser import HTMLParser


@dataclass(frozen=True)
class SeoIssue:
    category: str
    title: str
    description: str
    severity: str
    remediation: str
    confidence: str | None
    evidence: str | None
    dedupe_key: str


class SeoHtmlParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._in_title = False
        self._title_parts: list[str] = []
        self.meta_description: str | None = None
        self.canonical_url: str | None = None
        self.h1_count = 0
        self.images_missing_alt = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_map = {key.lower(): value for key, value in attrs}
        tag_name = tag.lower()

        if tag_name == "title":
            self._in_title = True
        elif tag_name == "meta" and attrs_map.get("name", "").lower() == "description":
            self.meta_description = attrs_map.get("content")
        elif tag_name == "link" and attrs_map.get("rel", "").lower() == "canonical":
            self.canonical_url = attrs_map.get("href")
        elif tag_name == "h1":
            self.h1_count += 1
        elif tag_name == "img":
            alt_value = attrs_map.get("alt")
            if alt_value is None or not alt_value.strip():
                self.images_missing_alt += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._title_parts.append(data)

    @property
    def title(self) -> str | None:
        title = "".join(self._title_parts).strip()
        return title or None


def check_seo(
    *,
    page_url: str,
    status_code: int | None,
    content_type: str | None,
    page_title: str | None,
    html_content: str | None,
) -> list[SeoIssue]:
    if not _is_html_page(content_type):
        return []

    parser = SeoHtmlParser()
    if html_content:
        parser.feed(html_content)

    issues: list[SeoIssue] = []
    title = page_title or parser.title

    if title is None:
        issues.append(
            SeoIssue(
                category="seo",
                title="Missing page title",
                description="The page does not include a title tag.",
                severity="high",
                remediation="Add a unique and descriptive title tag for this page.",
                confidence="high",
                evidence=page_url,
                dedupe_key=f"{page_url}:missing-title",
            )
        )
    else:
        if len(title) < 15:
            issues.append(
                SeoIssue(
                    category="seo",
                    title="Page title too short",
                    description="The page title is shorter than recommended for search results.",
                    severity="low",
                    remediation="Expand the title to better describe the page content.",
                    confidence="medium",
                    evidence=title,
                    dedupe_key=f"{page_url}:short-title",
                )
            )
        elif len(title) > 65:
            issues.append(
                SeoIssue(
                    category="seo",
                    title="Page title too long",
                    description="The page title may be truncated in search results.",
                    severity="low",
                    remediation="Shorten the title while keeping the key topic visible.",
                    confidence="medium",
                    evidence=title,
                    dedupe_key=f"{page_url}:long-title",
                )
            )

    meta_description = parser.meta_description.strip() if parser.meta_description else None
    if meta_description is None:
        issues.append(
            SeoIssue(
                category="seo",
                title="Missing meta description",
                description="The page does not include a meta description.",
                severity="medium",
                remediation="Add a concise meta description summarizing the page.",
                confidence="high",
                evidence=page_url,
                dedupe_key=f"{page_url}:missing-meta-description",
            )
        )
    else:
        if len(meta_description) < 50:
            issues.append(
                SeoIssue(
                    category="seo",
                    title="Meta description too short",
                    description="The meta description is shorter than recommended.",
                    severity="low",
                    remediation="Expand the meta description to better summarize the page.",
                    confidence="medium",
                    evidence=meta_description,
                    dedupe_key=f"{page_url}:short-meta-description",
                )
            )
        elif len(meta_description) > 160:
            issues.append(
                SeoIssue(
                    category="seo",
                    title="Meta description too long",
                    description="The meta description may be truncated in search results.",
                    severity="low",
                    remediation="Shorten the meta description to keep the key message visible.",
                    confidence="medium",
                    evidence=meta_description,
                    dedupe_key=f"{page_url}:long-meta-description",
                )
            )

    if not parser.canonical_url:
        issues.append(
            SeoIssue(
                category="seo",
                title="Missing canonical URL",
                description="The page does not declare a canonical URL.",
                severity="low",
                remediation="Add a canonical link element to help search engines index the preferred URL.",
                confidence="medium",
                evidence=page_url,
                dedupe_key=f"{page_url}:missing-canonical",
            )
        )

    if parser.h1_count == 0:
        issues.append(
            SeoIssue(
                category="seo",
                title="Missing H1 heading",
                description="The page does not include an H1 heading.",
                severity="medium",
                remediation="Add a clear H1 heading that describes the page topic.",
                confidence="high",
                evidence=page_url,
                dedupe_key=f"{page_url}:missing-h1",
            )
        )
    elif parser.h1_count > 1:
        issues.append(
            SeoIssue(
                category="seo",
                title="Multiple H1 headings",
                description="The page includes multiple H1 headings.",
                severity="low",
                remediation="Use one primary H1 and move secondary headings to H2 or lower.",
                confidence="high",
                evidence=f"{parser.h1_count} H1 tags",
                dedupe_key=f"{page_url}:multiple-h1",
            )
        )

    if parser.images_missing_alt > 0:
        issues.append(
            SeoIssue(
                category="seo",
                title="Images missing alt text",
                description="One or more images are missing alt text.",
                severity="low",
                remediation="Add meaningful alt text to informative images.",
                confidence="medium",
                evidence=f"{parser.images_missing_alt} images without alt text",
                dedupe_key=f"{page_url}:images-missing-alt",
            )
        )

    if status_code in {301, 302}:
        issues.append(
            SeoIssue(
                category="seo",
                title="Redirecting URL discovered",
                description="The page responds with a redirect, which can dilute crawl efficiency and internal linking quality.",
                severity="low",
                remediation="Link directly to the final destination URL where possible.",
                confidence="high",
                evidence=str(status_code),
                dedupe_key=f"{page_url}:seo-redirect",
            )
        )

    if status_code is not None and status_code != 200 and status_code not in {301, 302}:
        issues.append(
            SeoIssue(
                category="seo",
                title="Non-200 HTML page discovered",
                description="A crawlable HTML page responded with a non-200 status code.",
                severity="medium",
                remediation="Return a stable 200 response for indexable pages or remove them from internal discovery paths.",
                confidence="high",
                evidence=str(status_code),
                dedupe_key=f"{page_url}:non-200-html",
            )
        )

    return issues


def _is_html_page(content_type: str | None) -> bool:
    return bool(content_type and "text/html" in content_type.lower())
