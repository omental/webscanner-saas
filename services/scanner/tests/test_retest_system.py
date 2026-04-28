from datetime import datetime, timezone
from types import SimpleNamespace

from fastapi.testclient import TestClient

from app.api.deps import get_current_user, get_db_session
from app.main import app
from app.models.finding import Finding
from app.models.scan import Scan
from app.services.comparison_service import (
    EXISTING,
    FIXED,
    NEW,
    STILL_VULNERABLE,
    compare_finding_sets,
)


def _finding(
    *,
    finding_id: int,
    scan_id: int,
    title: str = "Missing Content-Security-Policy",
    request_url: str = "https://example.com/",
    parameter: str | None = None,
) -> Finding:
    return Finding(
        id=finding_id,
        scan_id=scan_id,
        scan_page_id=None,
        category="missing_security_header",
        title=title,
        description="desc",
        severity="medium",
        confidence="high",
        confidence_level="high",
        confidence_score=80,
        evidence_type="weak_signal",
        verification_steps=["Replay request."],
        request_url=request_url,
        tested_parameter=parameter,
        affected_parameter=parameter,
        deduplication_key=f"finding:v1:scan-{scan_id}:{title}:{parameter}",
        evidence="evidence",
        remediation="fix",
        is_confirmed=False,
        references=[],
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


def test_retest_marks_disappeared_issue_fixed() -> None:
    old = _finding(finding_id=1, scan_id=10)

    comparison = compare_finding_sets(
        previous_scan_id=10,
        current_scan_id=11,
        previous_findings=[old],
        current_findings=[],
    )

    assert comparison.summary["fixed"] == 1
    assert old.comparison_status == FIXED


def test_retest_marks_same_issue_still_vulnerable_and_existing() -> None:
    old = _finding(finding_id=1, scan_id=10, request_url="https://example.com/login")
    new = _finding(finding_id=2, scan_id=11, request_url="https://example.com/login")

    comparison = compare_finding_sets(
        previous_scan_id=10,
        current_scan_id=11,
        previous_findings=[old],
        current_findings=[new],
    )

    assert comparison.summary["still_vulnerable"] == 1
    assert comparison.summary["existing"] == 1
    assert old.comparison_status == STILL_VULNERABLE
    assert new.comparison_status == EXISTING


def test_retest_marks_new_issue_new() -> None:
    old = _finding(finding_id=1, scan_id=10, title="Missing X-Frame-Options")
    new = _finding(finding_id=2, scan_id=11, title="Missing Referrer-Policy")

    comparison = compare_finding_sets(
        previous_scan_id=10,
        current_scan_id=11,
        previous_findings=[old],
        current_findings=[new],
    )

    assert comparison.summary["fixed"] == 1
    assert comparison.summary["new"] == 1
    assert new.comparison_status == NEW


def test_compare_without_previous_scan_is_safe_fallback() -> None:
    current = _finding(finding_id=2, scan_id=11)

    comparison = compare_finding_sets(
        previous_scan_id=None,
        current_scan_id=11,
        previous_findings=[],
        current_findings=[current],
    )

    assert comparison.previous_scan_id is None
    assert comparison.summary == {
        "fixed": 0,
        "still_vulnerable": 0,
        "new": 0,
        "existing": 0,
        "not_retested": 0,
    }
    assert current.comparison_status is None


async def _fake_session():
    yield SimpleNamespace()


async def _fake_current_user() -> SimpleNamespace:
    return SimpleNamespace(id=1, role="admin", organization_id=1, status="active")


def test_retest_endpoint_creates_linked_scan(monkeypatch) -> None:
    previous = Scan(
        id=10,
        user_id=7,
        organization_id=1,
        target_id=3,
        scan_type="full",
        scan_profile="deep",
        status="completed",
        total_pages_found=2,
        total_findings=1,
        max_depth=4,
        max_pages=25,
        timeout_seconds=30,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    created = Scan(
        id=11,
        user_id=7,
        organization_id=1,
        target_id=3,
        scan_type="full",
        scan_profile="deep",
        status="queued",
        total_pages_found=0,
        total_findings=0,
        max_depth=4,
        max_pages=25,
        timeout_seconds=30,
        previous_scan_id=10,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    async def fake_require_scan_access(_session, scan_id: int, _admin):
        assert scan_id == 10
        return previous

    async def fake_create_scan_for_actor(_session, payload, _admin):
        assert payload.target_id == previous.target_id
        assert payload.scan_profile == "deep"
        assert payload.previous_scan_id == previous.id
        return created

    async def fake_run_scan(_scan_id: int) -> None:
        return None

    app.dependency_overrides[get_db_session] = _fake_session
    app.dependency_overrides[get_current_user] = _fake_current_user
    monkeypatch.setattr(
        "app.api.routes.scans.require_scan_access", fake_require_scan_access
    )
    monkeypatch.setattr(
        "app.api.routes.scans.create_scan_for_actor", fake_create_scan_for_actor
    )
    monkeypatch.setattr("app.api.routes.scans.run_scan", fake_run_scan)

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scans/10/retest", headers={"X-Current-User-Id": "1"}
        )

    app.dependency_overrides.clear()

    assert response.status_code == 201
    assert response.json()["previous_scan_id"] == 10
