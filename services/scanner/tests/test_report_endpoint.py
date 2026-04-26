from collections.abc import AsyncGenerator
from datetime import datetime, timezone
from types import SimpleNamespace

from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.api.deps import get_current_user, get_db_session
from app.main import app
from app.services.report_service import ReportSnapshot


async def _fake_session() -> AsyncGenerator[SimpleNamespace, None]:
    yield SimpleNamespace()


async def _fake_current_user() -> SimpleNamespace:
    return SimpleNamespace(id=1, role="admin", organization_id=1, status="active")


async def _fake_scan_access(*_args, **_kwargs) -> None:
    return None


def test_report_endpoint_returns_pdf_for_completed_scan(monkeypatch) -> None:
    async def fake_get_scan_report_pdf(_session, scan_id: int) -> bytes:
        assert scan_id == 7
        return b"%PDF-1.4 mock report"

    app.dependency_overrides[get_db_session] = _fake_session
    app.dependency_overrides[get_current_user] = _fake_current_user
    monkeypatch.setattr("app.api.routes.scans.require_scan_access", _fake_scan_access)
    monkeypatch.setattr(
        "app.api.routes.scans.get_scan_report_pdf", fake_get_scan_report_pdf
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/scans/7/report.pdf", headers={"X-Current-User-Id": "1"}
        )

    app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/pdf")
    assert 'scan-7-report.pdf' in response.headers["content-disposition"]
    assert response.content.startswith(b"%PDF-1.4")


def test_report_endpoint_rejects_non_completed_scan(monkeypatch) -> None:
    async def fake_get_scan_report_pdf(_session, _scan_id: int) -> bytes:
        raise HTTPException(
            status_code=400, detail="Scan must be completed before downloading a report"
        )

    app.dependency_overrides[get_db_session] = _fake_session
    app.dependency_overrides[get_current_user] = _fake_current_user
    monkeypatch.setattr("app.api.routes.scans.require_scan_access", _fake_scan_access)
    monkeypatch.setattr(
        "app.api.routes.scans.get_scan_report_pdf", fake_get_scan_report_pdf
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/scans/3/report.pdf", headers={"X-Current-User-Id": "1"}
        )

    app.dependency_overrides.clear()

    assert response.status_code == 400
    assert response.json()["detail"] == "Scan must be completed before downloading a report"


def test_report_endpoint_returns_404_for_missing_scan(monkeypatch) -> None:
    async def fake_get_scan_report_pdf(_session, _scan_id: int) -> bytes:
        raise HTTPException(status_code=404, detail="Scan not found")

    app.dependency_overrides[get_db_session] = _fake_session
    app.dependency_overrides[get_current_user] = _fake_current_user
    monkeypatch.setattr("app.api.routes.scans.require_scan_access", _fake_scan_access)
    monkeypatch.setattr(
        "app.api.routes.scans.get_scan_report_pdf", fake_get_scan_report_pdf
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/scans/999/report.pdf", headers={"X-Current-User-Id": "1"}
        )

    app.dependency_overrides.clear()

    assert response.status_code == 404
    assert response.json()["detail"] == "Scan not found"


def test_build_scan_report_pdf_contains_expected_text() -> None:
    from app.services.report_service import build_scan_report_pdf

    snapshot = ReportSnapshot(
        scan_id=4,
        target_domain="example.com",
        target_base_url="https://example.com",
        status="completed",
        scan_type="full",
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
        total_pages_found=2,
        total_findings=1,
        findings=[],
        technologies=[],
        pages=[],
    )

    pdf_bytes = build_scan_report_pdf(snapshot)

    assert pdf_bytes.startswith(b"%PDF")
