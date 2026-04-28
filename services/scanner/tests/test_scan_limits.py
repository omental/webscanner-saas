import asyncio
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.scanner.crawler import SafeCrawler
from app.schemas.scan import ScanCreate
from app.services import scan_runner_service


def test_scan_create_accepts_nullable_limit_overrides() -> None:
    payload = ScanCreate(user_id=1, target_id=2, scan_type="full")

    assert payload.max_depth is None
    assert payload.max_pages is None
    assert payload.timeout_seconds is None
    assert payload.scan_profile == "standard"


def test_scan_create_validates_scan_profile() -> None:
    assert (
        ScanCreate(user_id=1, target_id=2, scan_type="full", scan_profile="passive")
        .scan_profile
        == "passive"
    )

    with pytest.raises(ValidationError):
        ScanCreate(user_id=1, target_id=2, scan_type="full", scan_profile="nope")


def test_scan_create_rejects_invalid_limit_values() -> None:
    with pytest.raises(ValidationError):
        ScanCreate(user_id=1, target_id=2, scan_type="full", max_depth=11)

    with pytest.raises(ValidationError):
        ScanCreate(user_id=1, target_id=2, scan_type="full", max_pages=0)

    with pytest.raises(ValidationError):
        ScanCreate(user_id=1, target_id=2, scan_type="full", timeout_seconds=2)


def test_crawler_uses_default_limits_when_no_overrides() -> None:
    crawler = SafeCrawler(
        session=SimpleNamespace(),
        scan_id=1,
        base_url="https://example.com",
    )

    assert crawler.max_depth == scan_runner_service.settings.scanner_max_depth
    assert crawler.max_pages == scan_runner_service.settings.scanner_max_pages
    assert crawler.timeout_seconds == scan_runner_service.settings.scanner_timeout_seconds


def test_crawler_uses_provided_limits() -> None:
    crawler = SafeCrawler(
        session=SimpleNamespace(),
        scan_id=1,
        base_url="https://example.com",
        max_depth=4,
        max_pages=50,
        timeout_seconds=12,
    )

    assert crawler.max_depth == 4
    assert crawler.max_pages == 50
    assert crawler.timeout_seconds == 12


def test_runner_passes_scan_specific_limits_to_crawler(monkeypatch) -> None:
    captured: dict[str, object] = {}
    scan = SimpleNamespace(
        id=7,
        target_id=9,
        scan_profile="standard",
        max_depth=3,
        max_pages=42,
        timeout_seconds=11,
        total_pages_found=0,
    )
    target = SimpleNamespace(base_url="https://example.com")

    async def fake_not_cancelled(_session, _scan_id):
        return False

    async def fake_get_scan_by_id(_session, _scan_id):
        return scan

    async def fake_get_target_by_id(_session, _target_id):
        return target

    async def fake_mark_scan_running(_session, _scan):
        return _scan

    async def fake_mark_scan_completed(
        _session, _scan, total_pages_found, total_findings
    ):
        captured["completed"] = (total_pages_found, total_findings)
        return _scan

    async def fake_count_findings_for_scan(_session, _scan_id):
        return 0

    async def fake_noop(*_args, **_kwargs):
        return None

    class CapturingCrawler:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        async def crawl(self):
            return SimpleNamespace(total_pages_found=1, html_bodies_by_page_id={})

    class Session:
        async def rollback(self):
            raise AssertionError("rollback should not be called")

    monkeypatch.setattr(scan_runner_service, "_is_scan_cancelled", fake_not_cancelled)
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
    monkeypatch.setattr(scan_runner_service, "_run_crawl_checks", fake_noop)
    monkeypatch.setattr(
        scan_runner_service, "_run_subdomain_discovery_checks", fake_noop
    )
    monkeypatch.setattr(scan_runner_service, "_run_waf_detection_checks", fake_noop)
    monkeypatch.setattr(scan_runner_service, "_run_csrf_checks", fake_noop)
    monkeypatch.setattr(scan_runner_service, "_run_file_upload_checks", fake_noop)
    monkeypatch.setattr(scan_runner_service, "_run_file_upload_advanced_checks", fake_noop)
    monkeypatch.setattr(scan_runner_service, "_run_cookie_checks", fake_noop)
    monkeypatch.setattr(scan_runner_service, "_run_auth_surface_checks", fake_noop)
    monkeypatch.setattr(scan_runner_service, "_run_auth_advanced_checks", fake_noop)
    monkeypatch.setattr(scan_runner_service, "_run_cors_checks", fake_noop)
    monkeypatch.setattr(scan_runner_service, "_run_header_checks", fake_noop)
    monkeypatch.setattr(scan_runner_service, "_run_info_disclosure_checks", fake_noop)
    monkeypatch.setattr(scan_runner_service, "_run_exposure_path_checks", fake_noop)
    monkeypatch.setattr(scan_runner_service, "_run_fingerprinting", fake_noop)
    monkeypatch.setattr(scan_runner_service, "_run_performance_checks", fake_noop)
    monkeypatch.setattr(scan_runner_service, "_run_seo_checks", fake_noop)
    monkeypatch.setattr(scan_runner_service, "_run_active_checks", fake_noop)
    monkeypatch.setattr(scan_runner_service, "_run_rce_checks", fake_noop)
    monkeypatch.setattr(scan_runner_service, "_run_ssrf_checks", fake_noop)
    monkeypatch.setattr(scan_runner_service, "_run_stored_xss_checks", fake_noop)
    monkeypatch.setattr(scan_runner_service, "enrich_scan_findings", fake_noop)
    monkeypatch.setattr(scan_runner_service, "SafeCrawler", CapturingCrawler)

    asyncio.run(scan_runner_service._run_scan(Session(), 7))

    assert captured["max_depth"] == 3
    assert captured["max_pages"] == 42
    assert captured["timeout_seconds"] == 11


def test_passive_profile_uses_shallow_crawl_and_skips_intrusive_checks(monkeypatch) -> None:
    captured: dict[str, object] = {}
    calls: list[str] = []
    scan = SimpleNamespace(
        id=8,
        target_id=9,
        scan_profile="passive",
        max_depth=None,
        max_pages=None,
        timeout_seconds=None,
        total_pages_found=0,
    )
    target = SimpleNamespace(base_url="https://example.com")

    async def fake_not_cancelled(_session, _scan_id):
        return False

    async def fake_get_scan_by_id(_session, _scan_id):
        return scan

    async def fake_get_target_by_id(_session, _target_id):
        return target

    async def fake_mark_scan_running(_session, _scan):
        return _scan

    async def fake_mark_scan_completed(
        _session, _scan, total_pages_found, total_findings
    ):
        captured["completed"] = (total_pages_found, total_findings)
        return _scan

    async def fake_count_findings_for_scan(_session, _scan_id):
        return 0

    def recorder(name):
        async def fake(*_args, **_kwargs):
            calls.append(name)

        return fake

    class CapturingCrawler:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        async def crawl(self):
            return SimpleNamespace(total_pages_found=1, html_bodies_by_page_id={})

    class Session:
        async def rollback(self):
            raise AssertionError("rollback should not be called")

    monkeypatch.setattr(scan_runner_service, "_is_scan_cancelled", fake_not_cancelled)
    monkeypatch.setattr(scan_runner_service, "get_scan_by_id", fake_get_scan_by_id)
    monkeypatch.setattr(scan_runner_service, "get_target_by_id", fake_get_target_by_id)
    monkeypatch.setattr(scan_runner_service, "mark_scan_running", fake_mark_scan_running)
    monkeypatch.setattr(
        scan_runner_service, "mark_scan_completed", fake_mark_scan_completed
    )
    monkeypatch.setattr(
        scan_runner_service, "count_findings_for_scan", fake_count_findings_for_scan
    )
    for name in (
        "transport",
        "crawl",
        "subdomain_discovery",
        "waf_detection",
        "csrf",
        "file_upload",
        "file_upload_advanced",
        "cookies",
        "auth_surface",
        "auth_advanced",
        "cors",
        "headers",
        "info_disclosure",
        "exposure_paths",
        "fingerprinting",
        "performance",
        "seo",
        "active",
        "rce",
        "ssrf",
        "stored_xss",
    ):
        function_name = {
            "fingerprinting": "_run_fingerprinting",
            "subdomain_discovery": "_run_subdomain_discovery_checks",
            "exposure_paths": "_run_exposure_path_checks",
            "cookies": "_run_cookie_checks",
            "headers": "_run_header_checks",
        }.get(name, "_run_" + name + "_checks")
        monkeypatch.setattr(scan_runner_service, function_name, recorder(name))
    monkeypatch.setattr(scan_runner_service, "enrich_scan_findings", recorder("enrich"))
    monkeypatch.setattr(scan_runner_service, "SafeCrawler", CapturingCrawler)

    asyncio.run(scan_runner_service._run_scan(Session(), 8))

    assert captured["max_depth"] == 1
    assert captured["max_pages"] == 10
    assert "headers" in calls
    assert "fingerprinting" in calls
    assert "active" not in calls
    assert "rce" not in calls
    assert "ssrf" not in calls
