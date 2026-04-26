import asyncio
from types import SimpleNamespace

from app.scanner.crawler import SafeCrawler
from app.scanner.http_client import is_text_content_type
from app.scanner.utils import is_static_asset_url
from app.services import scan_runner_service


class FakeSession:
    def __init__(self) -> None:
        self.added: list[object] = []
        self.flush_count = 0
        self.commit_count = 0

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        self.flush_count += 1

    async def commit(self) -> None:
        self.commit_count += 1


def test_crawl_loop_exits_and_persists_first_page(monkeypatch) -> None:
    session = FakeSession()

    class FakeHttpClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def get(self, url: str):
            return SimpleNamespace(
                url=url,
                status_code=200,
                content_type="text/html",
                response_time_ms=12,
                headers={"content-type": "text/html"},
                body='<html><head><title>Home</title></head><body><a href="/">Home</a></body></html>',
                error=None,
            )

    monkeypatch.setattr("app.scanner.crawler.HttpClient", FakeHttpClient)

    crawler = SafeCrawler(
        session=session,
        scan_id=1,
        base_url="https://example.com",
        max_depth=2,
        max_pages=5,
    )

    result = asyncio.run(crawler.crawl())

    assert result.total_pages_found == 1
    assert len(result.html_bodies_by_page_id) == 1
    assert session.commit_count >= 1
    assert len(session.added) == 1
    assert session.added[0].response_body_excerpt is not None


def test_html_page_enqueues_internal_links(monkeypatch) -> None:
    session = FakeSession()
    responses = {
        "https://example.com": SimpleNamespace(
            url="https://example.com",
            status_code=200,
            content_type="text/html",
            response_time_ms=10,
            headers={"content-type": "text/html"},
            body=(
                '<html><body>'
                '<a href="/about">About</a>'
                '<a href="/contact">Contact</a>'
                '<a href="/static/logo.png">Logo</a>'
                '</body></html>'
            ),
            error=None,
        ),
        "https://example.com/about": SimpleNamespace(
            url="https://example.com/about",
            status_code=200,
            content_type="text/html",
            response_time_ms=9,
            headers={"content-type": "text/html"},
            body="<html><body>About</body></html>",
            error=None,
        ),
        "https://example.com/contact": SimpleNamespace(
            url="https://example.com/contact",
            status_code=200,
            content_type="text/html",
            response_time_ms=9,
            headers={"content-type": "text/html"},
            body="<html><body>Contact</body></html>",
            error=None,
        ),
    }

    class FakeHttpClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def get(self, url: str):
            return responses[url]

    monkeypatch.setattr("app.scanner.crawler.HttpClient", FakeHttpClient)

    crawler = SafeCrawler(
        session=session,
        scan_id=10,
        base_url="https://example.com",
        max_depth=2,
        max_pages=10,
    )

    result = asyncio.run(crawler.crawl())

    assert result.total_pages_found == 3
    stored_urls = [page.url for page in session.added]
    assert "https://example.com/about" in stored_urls
    assert "https://example.com/contact" in stored_urls
    assert "https://example.com/static/logo.png" not in stored_urls


def test_text_content_type_detection() -> None:
    assert is_text_content_type("text/html; charset=utf-8") is True
    assert is_text_content_type("text/css") is True
    assert is_text_content_type("application/json") is True
    assert is_text_content_type("application/javascript") is True
    assert is_text_content_type("image/png") is False
    assert is_text_content_type("application/octet-stream") is False


def test_static_asset_detection_does_not_skip_normal_pages() -> None:
    assert is_static_asset_url("https://example.com/logo.png") is True
    assert is_static_asset_url("https://example.com/app.js") is True
    assert is_static_asset_url("https://example.com/about") is False
    assert is_static_asset_url("https://example.com/blog/post-1") is False


def test_crawler_skips_binary_response_body_excerpt(monkeypatch) -> None:
    session = FakeSession()

    class FakeHttpClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def get(self, url: str):
            return SimpleNamespace(
                url=url,
                status_code=200,
                content_type="image/png",
                response_time_ms=8,
                headers={"content-type": "image/png"},
                body=None,
                error=None,
            )

    monkeypatch.setattr("app.scanner.crawler.HttpClient", FakeHttpClient)

    crawler = SafeCrawler(
        session=session,
        scan_id=2,
        base_url="https://example.com/logo.png",
        max_depth=0,
        max_pages=1,
    )

    result = asyncio.run(crawler.crawl())

    assert result.total_pages_found == 1
    assert result.html_bodies_by_page_id == {}
    assert session.added[0].response_body_excerpt is None


def test_crawler_respects_max_pages(monkeypatch) -> None:
    session = FakeSession()
    responses = {
        "https://example.com": SimpleNamespace(
            url="https://example.com",
            status_code=200,
            content_type="text/html",
            response_time_ms=10,
            headers={"content-type": "text/html"},
            body=(
                '<html><body>'
                '<a href="/a">A</a>'
                '<a href="/b">B</a>'
                '<a href="/c">C</a>'
                '</body></html>'
            ),
            error=None,
        ),
        "https://example.com/a": SimpleNamespace(
            url="https://example.com/a",
            status_code=200,
            content_type="text/html",
            response_time_ms=9,
            headers={"content-type": "text/html"},
            body="<html><body>A</body></html>",
            error=None,
        ),
        "https://example.com/b": SimpleNamespace(
            url="https://example.com/b",
            status_code=200,
            content_type="text/html",
            response_time_ms=9,
            headers={"content-type": "text/html"},
            body="<html><body>B</body></html>",
            error=None,
        ),
        "https://example.com/c": SimpleNamespace(
            url="https://example.com/c",
            status_code=200,
            content_type="text/html",
            response_time_ms=9,
            headers={"content-type": "text/html"},
            body="<html><body>C</body></html>",
            error=None,
        ),
    }

    class FakeHttpClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def get(self, url: str):
            return responses[url]

    monkeypatch.setattr("app.scanner.crawler.HttpClient", FakeHttpClient)

    crawler = SafeCrawler(
        session=session,
        scan_id=11,
        base_url="https://example.com",
        max_depth=3,
        max_pages=2,
    )

    result = asyncio.run(crawler.crawl())

    assert result.total_pages_found == 2


def test_runner_marks_failed_on_crawler_exception(monkeypatch) -> None:
    calls: dict[str, object] = {}
    scan = SimpleNamespace(id=3, target_id=9, total_pages_found=0)
    target = SimpleNamespace(base_url="https://example.com")

    async def fake_get_scan_by_id(_session, _scan_id):
        return scan

    async def fake_get_target_by_id(_session, _target_id):
        return target

    async def fake_mark_scan_running(_session, _scan):
        calls["running"] = True
        return _scan

    async def fake_mark_scan_failed(
        _session, _scan, total_pages_found, total_findings, error_message=None
    ):
        calls["failed"] = {
            "total_pages_found": total_pages_found,
            "total_findings": total_findings,
            "error_message": error_message,
        }
        return _scan

    async def fake_count_findings_for_scan(_session, _scan_id):
        return 0

    class BrokenCrawler:
        def __init__(self, **_kwargs):
            pass

        async def crawl(self):
            raise RuntimeError("crawler exploded")

    class SessionWithRollback:
        def __init__(self):
            self.rollback_called = False

        async def rollback(self):
            self.rollback_called = True
            calls["rollback"] = True

    monkeypatch.setattr(scan_runner_service, "get_scan_by_id", fake_get_scan_by_id)
    monkeypatch.setattr(scan_runner_service, "get_target_by_id", fake_get_target_by_id)
    monkeypatch.setattr(scan_runner_service, "mark_scan_running", fake_mark_scan_running)
    monkeypatch.setattr(scan_runner_service, "mark_scan_failed", fake_mark_scan_failed)
    monkeypatch.setattr(
        scan_runner_service, "count_findings_for_scan", fake_count_findings_for_scan
    )
    monkeypatch.setattr(scan_runner_service, "SafeCrawler", BrokenCrawler)

    session = SessionWithRollback()
    asyncio.run(scan_runner_service._run_scan(session, 3))

    assert calls["running"] is True
    assert calls["rollback"] is True
    assert "crawler exploded" in calls["failed"]["error_message"]


def test_runner_marks_completed_when_one_page_fetches(monkeypatch) -> None:
    calls: dict[str, object] = {}
    scan = SimpleNamespace(id=5, target_id=11, total_pages_found=0)
    target = SimpleNamespace(base_url="https://example.com")

    async def fake_get_scan_by_id(_session, _scan_id):
        return scan

    async def fake_get_target_by_id(_session, _target_id):
        return target

    async def fake_mark_scan_running(_session, _scan):
        calls["running"] = True
        return _scan

    async def fake_mark_scan_completed(
        _session, _scan, total_pages_found, total_findings
    ):
        calls["completed"] = {
            "total_pages_found": total_pages_found,
            "total_findings": total_findings,
        }
        return _scan

    async def fake_count_findings_for_scan(_session, _scan_id):
        return 0

    async def fake_noop(*_args, **_kwargs):
        return None

    class WorkingCrawler:
        def __init__(self, **_kwargs):
            pass

        async def crawl(self):
            return SimpleNamespace(total_pages_found=1)

    monkeypatch.setattr(scan_runner_service, "get_scan_by_id", fake_get_scan_by_id)
    monkeypatch.setattr(scan_runner_service, "get_target_by_id", fake_get_target_by_id)
    monkeypatch.setattr(scan_runner_service, "mark_scan_running", fake_mark_scan_running)
    monkeypatch.setattr(
        scan_runner_service, "mark_scan_completed", fake_mark_scan_completed
    )
    monkeypatch.setattr(
        scan_runner_service, "count_findings_for_scan", fake_count_findings_for_scan
    )
    monkeypatch.setattr(scan_runner_service, "_run_transport_checks", fake_noop)
    monkeypatch.setattr(scan_runner_service, "_run_header_checks", fake_noop)
    monkeypatch.setattr(scan_runner_service, "_run_info_disclosure_checks", fake_noop)
    monkeypatch.setattr(scan_runner_service, "_run_fingerprinting", fake_noop)
    monkeypatch.setattr(scan_runner_service, "_run_active_checks", fake_noop)
    monkeypatch.setattr(scan_runner_service, "enrich_scan_findings", fake_noop)
    monkeypatch.setattr(scan_runner_service, "SafeCrawler", WorkingCrawler)

    class SessionWithRollback:
        async def rollback(self):
            raise AssertionError("rollback should not be called on success")

    asyncio.run(scan_runner_service._run_scan(SessionWithRollback(), 5))

    assert calls["running"] is True
    assert calls["completed"]["total_pages_found"] == 1
    assert calls["completed"]["total_findings"] == 0


def test_runner_marks_failed_cleanly_if_enrichment_raises(monkeypatch) -> None:
    calls: dict[str, object] = {}
    scan = SimpleNamespace(id=7, target_id=13, total_pages_found=1)
    target = SimpleNamespace(base_url="https://example.com")

    async def fake_get_scan_by_id(_session, _scan_id):
        return scan

    async def fake_get_target_by_id(_session, _target_id):
        return target

    async def fake_mark_scan_running(_session, _scan):
        calls["running"] = True
        return _scan

    async def fake_mark_scan_failed(
        _session, _scan, total_pages_found, total_findings, error_message=None
    ):
        calls["failed"] = {
            "total_pages_found": total_pages_found,
            "total_findings": total_findings,
            "error_message": error_message,
        }
        return _scan

    async def fake_count_findings_for_scan(_session, _scan_id):
        return 2

    async def fake_list_scan_pages(_session, _scan_id):
        return [SimpleNamespace(id=1)]

    async def fake_noop(*_args, **_kwargs):
        return None

    async def fake_enrichment(*_args, **_kwargs):
        raise RuntimeError("missing greenlet during enrichment")

    class WorkingCrawler:
        def __init__(self, **_kwargs):
            pass

        async def crawl(self):
            return SimpleNamespace(total_pages_found=1)

    class SessionWithRollback:
        async def rollback(self):
            calls["rollback"] = True

    monkeypatch.setattr(scan_runner_service, "get_scan_by_id", fake_get_scan_by_id)
    monkeypatch.setattr(scan_runner_service, "get_target_by_id", fake_get_target_by_id)
    monkeypatch.setattr(scan_runner_service, "mark_scan_running", fake_mark_scan_running)
    monkeypatch.setattr(scan_runner_service, "mark_scan_failed", fake_mark_scan_failed)
    monkeypatch.setattr(
        scan_runner_service, "count_findings_for_scan", fake_count_findings_for_scan
    )
    monkeypatch.setattr(scan_runner_service, "list_scan_pages", fake_list_scan_pages)
    monkeypatch.setattr(scan_runner_service, "_run_transport_checks", fake_noop)
    monkeypatch.setattr(scan_runner_service, "_run_header_checks", fake_noop)
    monkeypatch.setattr(scan_runner_service, "_run_info_disclosure_checks", fake_noop)
    monkeypatch.setattr(scan_runner_service, "_run_fingerprinting", fake_noop)
    monkeypatch.setattr(scan_runner_service, "_run_active_checks", fake_noop)
    monkeypatch.setattr(scan_runner_service, "enrich_scan_findings", fake_enrichment)
    monkeypatch.setattr(scan_runner_service, "SafeCrawler", WorkingCrawler)

    asyncio.run(scan_runner_service._run_scan(SessionWithRollback(), 7))

    assert calls["running"] is True
    assert calls["rollback"] is True
    assert calls["failed"]["total_pages_found"] == 1
    assert "missing greenlet during enrichment" in calls["failed"]["error_message"]
