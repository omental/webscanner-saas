from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.detected_technology import DetectedTechnology
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.scan_page import ScanPage
from app.schemas.scan import ScanCreate
from app.services.organization_service import require_organization
from app.services.subscription_service import check_org_subscription
from app.services.target_service import get_target_by_id
from app.services.usage_service import enforce_weekly_scan_limit
from app.services.usage_service import enforce_trial_scan_limit
from app.services.user_service import get_user_by_id


async def create_scan(session: AsyncSession, payload: ScanCreate) -> Scan:
    return await create_scan_for_actor(session, payload, actor=None)


async def create_scan_for_actor(session: AsyncSession, payload: ScanCreate, actor) -> Scan:
    user = await get_user_by_id(session, payload.user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    target = await get_target_by_id(session, payload.target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    if actor is not None:
        if actor.role == "team_member":
            raise HTTPException(status_code=403, detail="Team members cannot create scans")
        if actor.role == "admin":
            if actor.organization_id is None:
                raise HTTPException(status_code=403, detail="Organization required")
            if user.organization_id != actor.organization_id:
                raise HTTPException(status_code=403, detail="User is outside your organization")
            if target.organization_id != actor.organization_id:
                raise HTTPException(status_code=403, detail="Target is outside your organization")
            organization = await require_organization(session, actor.organization_id)
            check_org_subscription(organization)
            if organization.subscription_status == "trial":
                await enforce_trial_scan_limit(session, organization)
            else:
                await enforce_weekly_scan_limit(session, actor.organization_id)
        elif actor.role != "super_admin":
            raise HTTPException(status_code=403, detail="Scan creation not allowed")

    values = payload.model_dump()
    values["organization_id"] = target.organization_id or user.organization_id
    scan = Scan(**values)
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    return scan


async def list_scans(session: AsyncSession) -> list[Scan]:
    result = await session.execute(select(Scan).order_by(Scan.id.desc()))
    return list(result.scalars().all())


async def list_scans_for_actor(session: AsyncSession, actor) -> list[Scan]:
    query = select(Scan).order_by(Scan.id.desc())
    if actor.role != "super_admin":
        query = query.where(Scan.organization_id == actor.organization_id)
    result = await session.execute(query)
    return list(result.scalars().all())


async def require_scan_access(session: AsyncSession, scan_id: int, actor) -> Scan:
    scan = await get_scan_by_id(session, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if actor.role != "super_admin" and scan.organization_id != actor.organization_id:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


async def list_scan_pages(session: AsyncSession, scan_id: int) -> list[ScanPage]:
    result = await session.execute(
        select(ScanPage)
        .where(ScanPage.scan_id == scan_id)
        .order_by(ScanPage.id.desc())
    )
    return list(result.scalars().all())


async def list_findings(session: AsyncSession, scan_id: int) -> list[Finding]:
    result = await session.execute(
        select(Finding)
        .options(selectinload(Finding.references))
        .where(Finding.scan_id == scan_id)
        .order_by(Finding.id.desc())
    )
    return list(result.scalars().all())


async def list_detected_technologies(
    session: AsyncSession, scan_id: int
) -> list[DetectedTechnology]:
    result = await session.execute(
        select(DetectedTechnology)
        .where(DetectedTechnology.scan_id == scan_id)
        .order_by(DetectedTechnology.id.desc())
    )
    return list(result.scalars().all())


async def get_scan_by_id(session: AsyncSession, scan_id: int) -> Scan | None:
    result = await session.execute(select(Scan).where(Scan.id == scan_id))
    return result.scalar_one_or_none()


async def mark_scan_running(session: AsyncSession, scan: Scan) -> Scan:
    scan.status = "running"
    scan.started_at = datetime.now(timezone.utc)
    scan.finished_at = None
    scan.error_message = None
    await session.commit()
    await session.refresh(scan)
    return scan


async def mark_scan_completed(
    session: AsyncSession, scan: Scan, total_pages_found: int, total_findings: int
) -> Scan:
    scan.status = "completed"
    scan.total_pages_found = total_pages_found
    scan.total_findings = total_findings
    scan.error_message = None
    scan.finished_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(scan)
    return scan


async def mark_scan_failed(
    session: AsyncSession,
    scan: Scan,
    total_pages_found: int,
    total_findings: int,
    error_message: str | None = None,
) -> Scan:
    scan.status = "failed"
    scan.total_pages_found = total_pages_found
    scan.total_findings = total_findings
    scan.error_message = error_message[:1000] if error_message else None
    scan.finished_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(scan)
    return scan


async def cancel_scan(session: AsyncSession, scan_id: int) -> Scan:
    return await cancel_scan_for_actor(session, scan_id, actor=None)


async def cancel_scan_for_actor(session: AsyncSession, scan_id: int, actor) -> Scan:
    scan = await get_scan_by_id(session, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if actor is not None:
        if actor.role == "team_member":
            raise HTTPException(status_code=403, detail="Team members cannot cancel scans")
        if actor.role != "super_admin" and scan.organization_id != actor.organization_id:
            raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status.lower() in {"queued", "pending", "running"}:
        scan.status = "cancelled"
        scan.error_message = None
        scan.finished_at = datetime.now(timezone.utc)
        await session.commit()
        await session.refresh(scan)

    return scan
