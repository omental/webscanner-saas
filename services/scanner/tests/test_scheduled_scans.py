import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace

from app.models.scan import Scan
from app.models.scheduled_scan import ScheduledScan
from app.schemas.scheduled_scan import ScheduledScanCreate, ScheduledScanUpdate
from app.services import scheduled_scan_service


class Result:
    def __init__(self, items: list[object]) -> None:
        self.items = items

    def scalars(self):
        return self

    def all(self) -> list[object]:
        return self.items

    def scalar_one_or_none(self):
        return self.items[0] if self.items else None


class FakeSession:
    def __init__(self, execute_items: list[object] | None = None) -> None:
        self.added: list[object] = []
        self.execute_items = execute_items or []
        self.commits = 0

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def commit(self) -> None:
        self.commits += 1

    async def refresh(self, obj: object) -> None:
        now = datetime.now(timezone.utc)
        if getattr(obj, "id", None) is None:
            setattr(obj, "id", len(self.added))
        if getattr(obj, "created_at", None) is None:
            setattr(obj, "created_at", now)
        if getattr(obj, "updated_at", None) is None:
            setattr(obj, "updated_at", now)

    async def execute(self, _query):
        return Result(self.execute_items)


def _actor(role: str = "admin") -> SimpleNamespace:
    return SimpleNamespace(id=7, role=role, organization_id=3)


def _schedule(
    *,
    schedule_id: int = 1,
    frequency: str = "weekly",
    next_run_at: datetime | None = None,
) -> ScheduledScan:
    now = datetime.now(timezone.utc)
    return ScheduledScan(
        id=schedule_id,
        organization_id=3,
        target_id=11,
        created_by_user_id=7,
        scan_profile="standard",
        frequency=frequency,
        next_run_at=next_run_at or now,
        last_run_at=None,
        is_active=True,
        created_at=now,
        updated_at=now,
    )


def test_create_scheduled_scan(monkeypatch) -> None:
    async def fake_get_target_by_id(_session, target_id: int):
        return SimpleNamespace(id=target_id, organization_id=3)

    monkeypatch.setattr(
        scheduled_scan_service,
        "get_target_by_id",
        fake_get_target_by_id,
    )
    session = FakeSession()
    next_run_at = datetime(2026, 5, 1, 9, 0, tzinfo=timezone.utc)
    payload = ScheduledScanCreate(
        target_id=11,
        scan_profile="deep",
        frequency="weekly",
        next_run_at=next_run_at,
    )

    schedule = asyncio.run(
        scheduled_scan_service.create_scheduled_scan_for_actor(
            session, payload, _actor()
        )
    )

    assert schedule.target_id == 11
    assert schedule.organization_id == 3
    assert schedule.created_by_user_id == 7
    assert schedule.scan_profile == "deep"
    assert schedule.frequency == "weekly"
    assert schedule.next_run_at == next_run_at
    assert schedule.is_active is True


def test_update_scheduled_scan() -> None:
    schedule = _schedule()
    session = FakeSession([schedule])
    new_run_at = datetime(2026, 5, 8, 9, 0, tzinfo=timezone.utc)

    updated = asyncio.run(
        scheduled_scan_service.update_scheduled_scan_for_actor(
            session,
            schedule.id,
            ScheduledScanUpdate(
                scan_profile="aggressive",
                frequency="monthly",
                next_run_at=new_run_at,
            ),
            _actor(),
        )
    )

    assert updated.scan_profile == "aggressive"
    assert updated.frequency == "monthly"
    assert updated.next_run_at == new_run_at
    assert session.commits == 1


def test_disable_scheduled_scan() -> None:
    schedule = _schedule()
    session = FakeSession([schedule])

    disabled = asyncio.run(
        scheduled_scan_service.disable_scheduled_scan_for_actor(
            session, schedule.id, _actor()
        )
    )

    assert disabled.is_active is False


def test_due_schedule_creates_scan_and_updates_next_run(monkeypatch) -> None:
    run_at = datetime(2026, 5, 1, 9, 0, tzinfo=timezone.utc)
    schedule = _schedule(next_run_at=run_at)

    async def fake_create_scan_for_actor(_session, payload, actor):
        assert actor is None
        assert payload.user_id == schedule.created_by_user_id
        assert payload.target_id == schedule.target_id
        assert payload.scan_type == "scheduled"
        assert payload.scan_profile == "standard"
        return Scan(
            id=42,
            user_id=payload.user_id,
            organization_id=schedule.organization_id,
            target_id=payload.target_id,
            scan_type=payload.scan_type,
            scan_profile=payload.scan_profile,
            status="queued",
            total_pages_found=0,
            total_findings=0,
            created_at=run_at,
            updated_at=run_at,
        )

    monkeypatch.setattr(
        scheduled_scan_service,
        "create_scan_for_actor",
        fake_create_scan_for_actor,
    )
    session = FakeSession([schedule])

    runs = asyncio.run(scheduled_scan_service.run_due_scheduled_scans(session, run_at))

    assert len(runs) == 1
    assert runs[0].scan.id == 42
    assert schedule.last_run_at == run_at
    assert schedule.next_run_at == datetime(2026, 5, 8, 9, 0, tzinfo=timezone.utc)


def test_next_run_at_updates_for_monthly_end_of_month() -> None:
    next_run = scheduled_scan_service.calculate_next_run_at(
        datetime(2026, 1, 31, 9, 0, tzinfo=timezone.utc),
        "monthly",
    )

    assert next_run == datetime(2026, 2, 28, 9, 0, tzinfo=timezone.utc)
