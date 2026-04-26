import asyncio
from datetime import datetime
from types import SimpleNamespace

from app.scanner.crawler import SafeCrawler
from app.services import scan_runner_service
from app.services.scan_service import cancel_scan


class ScalarResult:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class FakeCancelSession:
    def __init__(self, scan):
        self.scan = scan
        self.commit_count = 0
        self.refresh_count = 0

    async def commit(self):
        self.commit_count += 1

    async def refresh(self, _obj):
        self.refresh_count += 1


def test_cancel_running_scan_sets_cancelled_and_finished_at(monkeypatch) -> None:
    scan = SimpleNamespace(id=1, status="running", finished_at=None, error_message="old")

    async def fake_get_scan_by_id(_session, _scan_id):
        return scan

    monkeypatch.setattr("app.services.scan_service.get_scan_by_id", fake_get_scan_by_id)

    session = FakeCancelSession(scan)
    updated = asyncio.run(cancel_scan(session, 1))

    assert updated.status == "cancelled"
    assert isinstance(updated.finished_at, datetime)
    assert updated.error_message is None
    assert session.commit_count == 1
    assert session.refresh_count == 1


def test_cancel_queued_scan_sets_cancelled_and_finished_at(monkeypatch) -> None:
    scan = SimpleNamespace(id=2, status="queued", finished_at=None, error_message=None)

    async def fake_get_scan_by_id(_session, _scan_id):
        return scan

    monkeypatch.setattr("app.services.scan_service.get_scan_by_id", fake_get_scan_by_id)

    updated = asyncio.run(cancel_scan(FakeCancelSession(scan), 2))

    assert updated.status == "cancelled"
    assert isinstance(updated.finished_at, datetime)


def test_runner_stops_before_crawl_when_scan_is_cancelled(monkeypatch) -> None:
    calls: dict[str, object] = {}
    scan = SimpleNamespace(id=3, target_id=9, status="cancelled")
    target = SimpleNamespace(base_url="https://example.com")

    class Session:
        async def execute(self, _query):
            return ScalarResult("cancelled")

    async def fake_get_scan_by_id(_session, _scan_id):
        return scan

    async def fake_get_target_by_id(_session, _target_id):
        return target

    async def fake_mark_scan_running(_session, _scan):
        calls["running"] = True
        return _scan

    class CrawlerShouldNotRun:
        def __init__(self, **_kwargs):
            calls["crawler"] = True

    monkeypatch.setattr(scan_runner_service, "get_scan_by_id", fake_get_scan_by_id)
    monkeypatch.setattr(scan_runner_service, "get_target_by_id", fake_get_target_by_id)
    monkeypatch.setattr(scan_runner_service, "mark_scan_running", fake_mark_scan_running)
    monkeypatch.setattr(scan_runner_service, "SafeCrawler", CrawlerShouldNotRun)

    asyncio.run(scan_runner_service._run_scan(Session(), 3))

    assert "running" not in calls
    assert "crawler" not in calls


def test_crawler_does_not_store_page_after_cancel(monkeypatch) -> None:
    class Session:
        def __init__(self):
            self.added = []

        def add(self, page):
            self.added.append(page)

        async def flush(self):
            return None

        async def commit(self):
            return None

        async def execute(self, _query):
            return None

    class FakeHttpClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, url):
            return SimpleNamespace(
                url=url,
                status_code=200,
                content_type="text/html",
                response_time_ms=10,
                headers={"content-type": "text/html"},
                body="<html><body>ok</body></html>",
                error=None,
            )

    checks = iter([False, False, True])

    async def should_cancel():
        return next(checks)

    monkeypatch.setattr("app.scanner.crawler.HttpClient", FakeHttpClient)
    session = Session()
    crawler = SafeCrawler(
        session=session,
        scan_id=4,
        base_url="https://example.com",
        max_depth=0,
        max_pages=1,
        should_cancel=should_cancel,
    )

    result = asyncio.run(crawler.crawl())

    assert result.total_pages_found == 0
    assert session.added == []


def test_cancelled_scan_prevents_finding_writes(monkeypatch) -> None:
    class Session:
        async def execute(self, _query):
            return ScalarResult("cancelled")

    async def fake_create_findings(*_args, **_kwargs):
        raise AssertionError("findings should not be written after cancellation")

    monkeypatch.setattr(
        scan_runner_service, "create_findings_if_missing", fake_create_findings
    )

    try:
        asyncio.run(
            scan_runner_service._create_findings_if_not_cancelled(
                Session(),
                scan_id=5,
                scan_page_id=None,
                issues=[object()],
            )
        )
    except scan_runner_service.ScanCancelled:
        pass
    else:
        raise AssertionError("Expected ScanCancelled")
