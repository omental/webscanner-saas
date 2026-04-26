from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.organization import Organization
from app.schemas.organization import OrganizationSubscriptionUpdate

SUBSCRIPTION_STATUSES = {"active", "trial", "expired", "suspended"}
EXPIRED_MESSAGE = "Your subscription has expired. Please upgrade to continue."
SUSPENDED_MESSAGE = "Your account is suspended. Contact support."
TRIAL_ENDED_MESSAGE = "Your trial has ended. Please choose a package."


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def check_org_subscription(
    organization: Organization, now: datetime | None = None
) -> None:
    current = now or datetime.now(timezone.utc)
    status = organization.subscription_status
    if status == "active":
        return
    if status == "suspended":
        raise HTTPException(status_code=403, detail=SUSPENDED_MESSAGE)
    if status == "expired":
        raise HTTPException(status_code=403, detail=EXPIRED_MESSAGE)
    if status == "trial":
        if organization.trial_ends_at is None:
            raise HTTPException(status_code=403, detail=TRIAL_ENDED_MESSAGE)
        if _as_utc(organization.trial_ends_at) <= current:
            raise HTTPException(status_code=403, detail=TRIAL_ENDED_MESSAGE)
        return
    raise HTTPException(status_code=403, detail=EXPIRED_MESSAGE)


async def update_subscription(
    session: AsyncSession,
    organization: Organization,
    payload: OrganizationSubscriptionUpdate,
) -> Organization:
    if payload.subscription_status not in SUBSCRIPTION_STATUSES:
        raise HTTPException(status_code=400, detail="Invalid subscription status")
    organization.subscription_status = payload.subscription_status
    organization.subscription_start = payload.subscription_start
    organization.subscription_end = payload.subscription_end
    organization.trial_ends_at = payload.trial_ends_at
    await session.commit()
    await session.refresh(organization)
    return organization


async def start_trial(
    session: AsyncSession, organization: Organization, days: int
) -> Organization:
    if days < 1:
        raise HTTPException(status_code=400, detail="Trial days must be positive")
    organization.subscription_status = "trial"
    now = datetime.now(timezone.utc)
    organization.subscription_start = now
    organization.trial_ends_at = now + timedelta(days=days)
    organization.subscription_end = organization.trial_ends_at
    await session.commit()
    await session.refresh(organization)
    return organization
