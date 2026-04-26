import logging
from collections import deque
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Iterable
from collections.abc import Awaitable, Callable
from urllib.parse import urljoin

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models.scan import Scan
from app.models.scan_page import ScanPage
from app.scanner.http_client import HttpClient
from app.scanner.utils import (
    is_static_asset_url,
    is_same_host,
    normalize_url,
    should_skip_url,
    strip_fragment,
)

settings = get_settings()
logger = logging.getLogger(__name__)


class LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self._inside_title = False
        self._title_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            for key, value in attrs:
                if key == "href" and value:
                    self.links.append(value)
        if tag == "title":
            self._inside_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._inside_title = False

    def handle_data(self, data: str) -> None:
        if self._inside_title:
            self._title_parts.append(data)

    @property
    def page_title(self) -> str | None:
        title = "".join(self._title_parts).strip()
        return title or None


@dataclass
class CrawlResult:
    total_pages_found: int
    html_bodies_by_page_id: dict[int, str]


class SafeCrawler:
    def __init__(
        self,
        session: AsyncSession,
        scan_id: int,
        base_url: str,
        max_depth: int | None = None,
        max_pages: int | None = None,
        timeout_seconds: int | None = None,
        should_cancel: Callable[[], Awaitable[bool]] | None = None,
    ) -> None:
        self.session = session
        self.scan_id = scan_id
        self.base_url = normalize_url(base_url)
        self.max_depth = settings.scanner_max_depth if max_depth is None else max_depth
        self.max_pages = settings.scanner_max_pages if max_pages is None else max_pages
        self.timeout_seconds = (
            settings.scanner_timeout_seconds if timeout_seconds is None else timeout_seconds
        )
        self.visited: set[str] = set()
        self.queued: set[str] = set()
        self.persisted_pages = 0
        self.should_cancel = should_cancel

    async def _cancel_requested(self) -> bool:
        return bool(self.should_cancel and await self.should_cancel())

    async def crawl(self) -> CrawlResult:
        queue = deque([(self.base_url, None, 0)])
        self.queued.add(self.base_url)
        html_bodies_by_page_id: dict[int, str] = {}

        async with HttpClient(timeout_seconds=self.timeout_seconds) as http_client:
            while queue and len(self.visited) < self.max_pages:
                if await self._cancel_requested():
                    logger.info("crawler cancelled scan_id=%s", self.scan_id)
                    break

                logger.info(
                    "crawler queue iteration start scan_id=%s queue_size=%s visited=%s",
                    self.scan_id,
                    len(queue),
                    len(self.visited),
                )
                url, discovered_from, depth = queue.popleft()
                self.queued.discard(url)

                if url in self.visited or depth > self.max_depth:
                    logger.info(
                        "crawler queue iteration end scan_id=%s skipped_url=%s depth=%s",
                        self.scan_id,
                        url,
                        depth,
                    )
                    continue

                self.visited.add(url)
                if await self._cancel_requested():
                    logger.info("crawler cancelled before fetch scan_id=%s url=%s", self.scan_id, url)
                    break

                fetch_result = await http_client.get(url)
                if fetch_result.error:
                    logger.warning(
                        "crawler fetch failed scan_id=%s url=%s error=%s",
                        self.scan_id,
                        url,
                        fetch_result.error,
                    )
                    continue
                logger.info(
                    "target fetch success scan_id=%s requested_url=%s final_url=%s status_code=%s",
                    self.scan_id,
                    url,
                    fetch_result.url,
                    fetch_result.status_code,
                )

                final_url = normalize_url(fetch_result.url)

                if not is_same_host(self.base_url, final_url):
                    logger.info(
                        "crawler skipped off-host final_url scan_id=%s url=%s final_url=%s",
                        self.scan_id,
                        url,
                        final_url,
                    )
                    continue

                page_title = None
                links: Iterable[str] = []
                if fetch_result.body and self._is_html(fetch_result.content_type):
                    extractor = LinkExtractor()
                    extractor.feed(fetch_result.body)
                    page_title = extractor.page_title
                    links = extractor.links
                    logger.info(
                        "crawler extracted links scan_id=%s url=%s link_count=%s",
                        self.scan_id,
                        final_url,
                        len(links),
                    )

                page = ScanPage(
                    scan_id=self.scan_id,
                    url=final_url,
                    method="GET",
                    status_code=fetch_result.status_code,
                    content_type=fetch_result.content_type,
                    response_time_ms=fetch_result.response_time_ms,
                    page_title=page_title,
                    response_headers=fetch_result.headers,
                    response_body_excerpt=(fetch_result.body or "")[:10000] or None,
                    discovered_from=discovered_from,
                    depth=depth,
                )
                if await self._cancel_requested():
                    logger.info("crawler cancelled before page persist scan_id=%s url=%s", self.scan_id, final_url)
                    break

                await self._persist_page(page)
                if fetch_result.body and self._is_html(fetch_result.content_type) and page.id is not None:
                    html_bodies_by_page_id[page.id] = fetch_result.body

                if depth >= self.max_depth:
                    logger.info(
                        "crawler queue iteration end scan_id=%s persisted_url=%s depth=%s queued=%s",
                        self.scan_id,
                        final_url,
                        depth,
                        len(queue),
                    )
                    continue

                for href in links:
                    candidate = strip_fragment(urljoin(final_url, href))
                    if should_skip_url(candidate):
                        logger.info(
                            "crawler skipped url scan_id=%s url=%s reason=skip_rule",
                            self.scan_id,
                            candidate,
                        )
                        continue
                    if not is_same_host(self.base_url, candidate):
                        continue

                    normalized_candidate = normalize_url(candidate)
                    if is_static_asset_url(normalized_candidate):
                        logger.info(
                            "crawler skipped url scan_id=%s url=%s reason=static_asset",
                            self.scan_id,
                            normalized_candidate,
                        )
                        continue
                    if (
                        normalized_candidate not in self.visited
                        and normalized_candidate not in self.queued
                    ):
                        queue.append((normalized_candidate, final_url, depth + 1))
                        self.queued.add(normalized_candidate)
                        logger.info(
                            "crawler enqueued url scan_id=%s url=%s depth=%s",
                            self.scan_id,
                            normalized_candidate,
                            depth + 1,
                        )

                logger.info(
                    "crawler queue iteration end scan_id=%s persisted_url=%s depth=%s queued=%s",
                    self.scan_id,
                    final_url,
                    depth,
                    len(queue),
                )

        return CrawlResult(
            total_pages_found=self.persisted_pages,
            html_bodies_by_page_id=html_bodies_by_page_id,
        )

    @staticmethod
    def _is_html(content_type: str | None) -> bool:
        return bool(content_type and "text/html" in content_type.lower())

    async def _persist_page(self, page: ScanPage) -> None:
        stage = "initial page persist" if self.persisted_pages == 0 else "page persist"
        logger.info(
            "%s start scan_id=%s url=%s depth=%s",
            stage,
            self.scan_id,
            page.url,
            page.depth,
        )
        self.session.add(page)
        await self.session.flush()
        await self.session.commit()
        self.persisted_pages += 1
        await self.session.execute(
            update(Scan)
            .where(Scan.id == self.scan_id)
            .values(total_pages_found=self.persisted_pages)
        )
        await self.session.commit()
        logger.info(
            "%s success scan_id=%s url=%s persisted_pages=%s",
            stage,
            self.scan_id,
            page.url,
            self.persisted_pages,
        )
