from datetime import datetime, time, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.organization import Organization
from app.models.invoice import Invoice
from app.models.scan import Scan
from app.schemas.usage import UsageRead

WEEKLY_LIMIT_REACHED = "Weekly scan limit reached for your current package."
TRIAL_SCAN_LIMIT = 1
TRIAL_LIMIT_REACHED = "Your free trial includes 1 scan. Upgrade to continue scanning."


def current_week_bounds(now: datetime | None = None) -> tuple[datetime, datetime]:
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    current = current.astimezone(timezone.utc)
    week_start_date = (current - timedelta(days=current.weekday())).date()
    week_start = datetime.combine(week_start_date, time.min, tzinfo=timezone.utc)
    return week_start, week_start + timedelta(days=7)


async def count_scans_this_week(
    session: AsyncSession, organization_id: int, now: datetime | None = None
) -> int:
    week_start, week_end = current_week_bounds(now)
    result = await session.execute(
        select(func.count(Scan.id)).where(
            Scan.organization_id == organization_id,
            Scan.created_at >= week_start,
            Scan.created_at < week_end,
        )
    )
    return int(result.scalar_one())


async def count_trial_scans(
    session: AsyncSession, organization: Organization
) -> int:
    start = organization.subscription_start
    end = organization.trial_ends_at
    query = select(func.count(Scan.id)).where(Scan.organization_id == organization.id)
    if start is not None:
        query = query.where(Scan.created_at >= start)
    if end is not None:
        query = query.where(Scan.created_at <= end)
    result = await session.execute(query)
    return int(result.scalar_one())


async def get_current_invoice(session: AsyncSession, organization_id: int) -> Invoice | None:
    result = await session.execute(
        select(Invoice)
        .where(Invoice.organization_id == organization_id)
        .order_by(Invoice.id.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def get_organization_usage(
    session: AsyncSession, organization: Organization, now: datetime | None = None
) -> UsageRead:
    week_start, week_end = current_week_bounds(now)
    used = await count_scans_this_week(session, organization.id, now)
    trial_used = await count_trial_scans(session, organization)
    limit = (
        organization.package.scan_limit_per_week
        if organization.package is not None
        else 0
    )
    remaining = max(limit - used, 0)
    trial_remaining = max(TRIAL_SCAN_LIMIT - trial_used, 0)
    invoice = await get_current_invoice(session, organization.id)
    is_trial = organization.subscription_status == "trial"
    is_blocked = (
        organization.subscription_status in {"expired", "suspended"}
        or (is_trial and trial_remaining <= 0)
        or (organization.subscription_status == "active" and remaining <= 0)
    )
    return UsageRead(
        organization_id=organization.id,
        organization_name=organization.name,
        package_name=organization.package.name if organization.package else None,
        subscription_status=organization.subscription_status,
        trial_ends_at=organization.trial_ends_at,
        subscription_end=organization.subscription_end,
        scan_limit_per_week=limit,
        scans_used_this_week=used,
        scans_remaining_this_week=remaining,
        trial_scan_limit=TRIAL_SCAN_LIMIT,
        trial_scans_used=trial_used,
        trial_scans_remaining=trial_remaining,
        is_trial_limit_reached=is_trial and trial_remaining <= 0,
        is_blocked=is_blocked,
        current_invoice_id=invoice.id if invoice else None,
        current_invoice_status=invoice.status if invoice else None,
        current_invoice_pdf_url=invoice.pdf_url if invoice else None,
        week_start=week_start,
        week_end=week_end,
        status=organization.status,
    )


async def get_usage_for_organization_id(
    session: AsyncSession, organization_id: int, now: datetime | None = None
) -> UsageRead:
    result = await session.execute(
        select(Organization)
        .options(selectinload(Organization.package))
        .where(Organization.id == organization_id)
    )
    organization = result.scalar_one_or_none()
    if organization is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    return await get_organization_usage(session, organization, now)


async def list_organization_usage(
    session: AsyncSession, now: datetime | None = None
) -> list[UsageRead]:
    result = await session.execute(
        select(Organization)
        .options(selectinload(Organization.package))
        .order_by(Organization.id.desc())
    )
    organizations = list(result.scalars().all())
    return [
        await get_organization_usage(session, organization, now)
        for organization in organizations
    ]


async def enforce_weekly_scan_limit(
    session: AsyncSession, organization_id: int, now: datetime | None = None
) -> None:
    usage = await get_usage_for_organization_id(session, organization_id, now)
    if usage.scans_remaining_this_week <= 0:
        raise HTTPException(status_code=403, detail=WEEKLY_LIMIT_REACHED)


async def enforce_trial_scan_limit(
    session: AsyncSession, organization: Organization
) -> None:
    used = await count_trial_scans(session, organization)
    if used >= TRIAL_SCAN_LIMIT:
        raise HTTPException(status_code=403, detail=TRIAL_LIMIT_REACHED)
