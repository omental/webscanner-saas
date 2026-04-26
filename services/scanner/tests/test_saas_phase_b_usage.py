import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace

from fastapi import HTTPException

from app.models.organization import Organization
from app.models.package import Package
from app.schemas.scan import ScanCreate
from app.services.scan_service import create_scan_for_actor
from app.services.usage_service import (
    WEEKLY_LIMIT_REACHED,
    current_week_bounds,
    enforce_weekly_scan_limit,
    list_organization_usage,
)


def make_org(package_name: str, limit: int, organization_id: int = 1) -> Organization:
    package = Package(
        id=organization_id,
        name=package_name,
        slug=package_name.lower(),
        scan_limit_per_week=limit,
        price_monthly=0,
        status="active",
    )
    organization = Organization(
        id=organization_id,
        name=f"{package_name} Org",
        slug=f"{package_name.lower()}-org",
        package_id=organization_id,
        status="active",
    )
    organization.package = package
    return organization


class UsageSession:
    def __init__(self, organizations: list[Organization], used: dict[int, int]) -> None:
        self.organizations = organizations
        self.used = used

    async def execute(self, statement):
        statement_text = str(statement)
        if "count(scans.id)" in statement_text.lower():
            organization_id = next(iter(self.used))
            if hasattr(statement, "compile"):
                for bind in statement.compile().params.values():
                    if isinstance(bind, int):
                        organization_id = bind
                        break
            count = self.used.get(organization_id, 0)

            class CountResult:
                def scalar_one(self):
                    return count

            return CountResult()

        if "WHERE organizations.id" in statement_text:
            organization = self.organizations[0]

            class OrgResult:
                def scalar_one_or_none(self):
                    return organization

            return OrgResult()

        organizations = self.organizations

        class OrgListResult:
            def scalars(self):
                return self

            def all(self):
                return organizations

        return OrgListResult()


def test_bronze_org_can_create_one_scan_only() -> None:
    session = UsageSession([make_org("Bronze", 1)], {1: 0})

    asyncio.run(enforce_weekly_scan_limit(session, 1))


def test_bronze_org_blocked_on_second_scan_same_week() -> None:
    session = UsageSession([make_org("Bronze", 1)], {1: 1})

    try:
        asyncio.run(enforce_weekly_scan_limit(session, 1))
    except HTTPException as exc:
        assert exc.status_code == 403
        assert exc.detail == WEEKLY_LIMIT_REACHED
    else:
        raise AssertionError("Expected weekly limit to block second Bronze scan")


def test_silver_org_allows_up_to_ten_scans() -> None:
    session = UsageSession([make_org("Silver", 10)], {1: 9})

    asyncio.run(enforce_weekly_scan_limit(session, 1))


def test_admin_cannot_bypass_limit(monkeypatch) -> None:
    session = SimpleNamespace()
    admin = SimpleNamespace(role="admin", organization_id=1)

    async def fake_get_user_by_id(_session, _user_id):
        return SimpleNamespace(id=_user_id, organization_id=1)

    async def fake_get_target_by_id(_session, _target_id):
        return SimpleNamespace(id=_target_id, organization_id=1)

    async def fake_require_organization(_session, _organization_id):
        return SimpleNamespace(subscription_status="active", trial_ends_at=None)

    async def fake_enforce(_session, _organization_id):
        raise HTTPException(status_code=403, detail=WEEKLY_LIMIT_REACHED)

    monkeypatch.setattr("app.services.scan_service.get_user_by_id", fake_get_user_by_id)
    monkeypatch.setattr(
        "app.services.scan_service.get_target_by_id", fake_get_target_by_id
    )
    monkeypatch.setattr(
        "app.services.scan_service.require_organization", fake_require_organization
    )
    monkeypatch.setattr("app.services.scan_service.enforce_weekly_scan_limit", fake_enforce)

    try:
        asyncio.run(
            create_scan_for_actor(
                session,
                ScanCreate(user_id=1, target_id=1, scan_type="full"),
                admin,
            )
        )
    except HTTPException as exc:
        assert exc.status_code == 403
        assert exc.detail == WEEKLY_LIMIT_REACHED
    else:
        raise AssertionError("Expected admin scan creation to honor package limit")


def test_team_member_cannot_create_scan_even_with_usage_available(monkeypatch) -> None:
    session = SimpleNamespace()
    team_member = SimpleNamespace(role="team_member", organization_id=1)

    async def fake_get_user_by_id(_session, _user_id):
        return SimpleNamespace(id=_user_id, organization_id=1)

    async def fake_get_target_by_id(_session, _target_id):
        return SimpleNamespace(id=_target_id, organization_id=1)

    monkeypatch.setattr("app.services.scan_service.get_user_by_id", fake_get_user_by_id)
    monkeypatch.setattr(
        "app.services.scan_service.get_target_by_id", fake_get_target_by_id
    )

    try:
        asyncio.run(
            create_scan_for_actor(
                session,
                ScanCreate(user_id=1, target_id=1, scan_type="full"),
                team_member,
            )
        )
    except HTTPException as exc:
        assert exc.status_code == 403
    else:
        raise AssertionError("Expected team member scan creation to be forbidden")


def test_super_admin_can_view_all_usage() -> None:
    organizations = [make_org("Bronze", 1, 1), make_org("Gold", 100, 2)]
    session = UsageSession(organizations, {1: 1, 2: 5})

    usage = asyncio.run(list_organization_usage(session))

    assert [row.organization_id for row in usage] == [1, 2]
    assert usage[0].scan_limit_per_week == 1
    assert usage[1].scan_limit_per_week == 100


def test_usage_resets_based_on_new_week() -> None:
    sunday = datetime(2026, 4, 26, 12, tzinfo=timezone.utc)
    monday = datetime(2026, 4, 27, 12, tzinfo=timezone.utc)

    sunday_start, sunday_end = current_week_bounds(sunday)
    monday_start, monday_end = current_week_bounds(monday)

    assert sunday_start.isoformat().startswith("2026-04-20")
    assert sunday_end == monday_start
    assert monday_end.isoformat().startswith("2026-05-04")
