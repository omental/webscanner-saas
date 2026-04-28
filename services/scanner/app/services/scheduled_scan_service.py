from __future__ import annotations

from calendar import monthrange
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import Scan
from app.models.scheduled_scan import ScheduledScan
from app.schemas.scan import ScanCreate
from app.schemas.scheduled_scan import ScheduledScanCreate, ScheduledScanUpdate
from app.services.scan_service import create_scan_for_actor
from app.services.target_service import get_target_by_id


@dataclass(slots=True)
class ScheduledScanRun:
    scheduled_scan: ScheduledScan
    scan: Scan


def calculate_next_run_at(
    current_run_at: datetime, frequency: str
) -> datetime:
    normalized = frequency.lower()
    if normalized == "weekly":
        return current_run_at + timedelta(days=7)
    if normalized == "monthly":
        year = current_run_at.year
        month = current_run_at.month + 1
        if month == 13:
            year += 1
            month = 1
        day = min(current_run_at.day, monthrange(year, month)[1])
        return current_run_at.replace(year=year, month=month, day=day)
    if normalized == "custom":
        return current_run_at + timedelta(days=1)
    raise HTTPException(status_code=400, detail="Unsupported schedule frequency")


async def create_scheduled_scan_for_actor(
    session: AsyncSession, payload: ScheduledScanCreate, actor
) -> ScheduledScan:
    if actor.role == "team_member":
        raise HTTPException(status_code=403, detail="Team members cannot schedule scans")
    if actor.role not in {"admin", "super_admin"}:
        raise HTTPException(status_code=403, detail="Schedule creation not allowed")

    target = await get_target_by_id(session, payload.target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    if actor.role != "super_admin" and target.organization_id != actor.organization_id:
        raise HTTPException(status_code=404, detail="Target not found")

    organization_id = target.organization_id or actor.organization_id
    if organization_id is None:
        raise HTTPException(status_code=403, detail="Organization required")

    schedule = ScheduledScan(
        organization_id=organization_id,
        target_id=payload.target_id,
        created_by_user_id=actor.id,
        scan_profile=payload.scan_profile,
        frequency=payload.frequency,
        next_run_at=payload.next_run_at,
        is_active=payload.is_active,
    )
    session.add(schedule)
    await session.commit()
    await session.refresh(schedule)
    return schedule


async def list_scheduled_scans_for_actor(
    session: AsyncSession, actor
) -> list[ScheduledScan]:
    query = select(ScheduledScan).order_by(ScheduledScan.id.desc())
    if actor.role != "super_admin":
        query = query.where(ScheduledScan.organization_id == actor.organization_id)
    result = await session.execute(query)
    return list(result.scalars().all())


async def get_scheduled_scan_by_id(
    session: AsyncSession, scheduled_scan_id: int
) -> ScheduledScan | None:
    result = await session.execute(
        select(ScheduledScan).where(ScheduledScan.id == scheduled_scan_id)
    )
    return result.scalar_one_or_none()


async def require_scheduled_scan_access(
    session: AsyncSession, scheduled_scan_id: int, actor
) -> ScheduledScan:
    schedule = await get_scheduled_scan_by_id(session, scheduled_scan_id)
    if schedule is None:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")
    if actor.role != "super_admin" and schedule.organization_id != actor.organization_id:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")
    return schedule


async def update_scheduled_scan_for_actor(
    session: AsyncSession,
    scheduled_scan_id: int,
    payload: ScheduledScanUpdate,
    actor,
) -> ScheduledScan:
    if actor.role == "team_member":
        raise HTTPException(status_code=403, detail="Team members cannot update schedules")
    schedule = await require_scheduled_scan_access(session, scheduled_scan_id, actor)
    values = payload.model_dump(exclude_unset=True)
    for field, value in values.items():
        setattr(schedule, field, value)
    await session.commit()
    await session.refresh(schedule)
    return schedule


async def disable_scheduled_scan_for_actor(
    session: AsyncSession, scheduled_scan_id: int, actor
) -> ScheduledScan:
    return await update_scheduled_scan_for_actor(
        session,
        scheduled_scan_id,
        ScheduledScanUpdate(is_active=False),
        actor,
    )


async def run_due_scheduled_scans(
    session: AsyncSession, now: datetime | None = None
) -> list[ScheduledScanRun]:
    run_at = now or datetime.now(timezone.utc)
    result = await session.execute(
        select(ScheduledScan)
        .where(ScheduledScan.is_active.is_(True))
        .where(ScheduledScan.next_run_at <= run_at)
        .order_by(ScheduledScan.next_run_at.asc(), ScheduledScan.id.asc())
    )
    schedules = list(result.scalars().all())
    runs: list[ScheduledScanRun] = []

    for schedule in schedules:
        scan = await create_scan_for_actor(
            session,
            ScanCreate(
                user_id=schedule.created_by_user_id,
                target_id=schedule.target_id,
                scan_type="scheduled",
                scan_profile=schedule.scan_profile or "standard",
            ),
            actor=None,
        )
        schedule.last_run_at = run_at
        schedule.next_run_at = calculate_next_run_at(run_at, schedule.frequency)
        session.add(schedule)
        await session.commit()
        await session.refresh(schedule)
        runs.append(ScheduledScanRun(scheduled_scan=schedule, scan=scan))

    return runs
