from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.target import Target
from app.scanner.utils import get_domain, normalize_url
from app.schemas.target import TargetCreate
from app.services.organization_service import require_organization
from app.services.subscription_service import (
    SUSPENDED_MESSAGE,
    TRIAL_ENDED_MESSAGE,
    _as_utc,
)
from app.services.user_service import get_user_by_id


async def create_target(session: AsyncSession, payload: TargetCreate) -> Target:
    return await create_target_for_actor(session, payload, actor=None)


async def create_target_for_actor(
    session: AsyncSession, payload: TargetCreate, actor
) -> Target:
    user = await get_user_by_id(session, payload.user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if actor is not None:
        if actor.role == "team_member":
            raise HTTPException(status_code=403, detail="Team members cannot create targets")
        if actor.role == "admin":
            if actor.organization_id is None:
                raise HTTPException(status_code=403, detail="Organization required")
            if user.organization_id != actor.organization_id:
                raise HTTPException(status_code=403, detail="User is outside your organization")
            organization = await require_organization(session, actor.organization_id)
            if organization.subscription_status == "suspended":
                raise HTTPException(status_code=403, detail=SUSPENDED_MESSAGE)
            if (
                organization.subscription_status == "trial"
                and organization.trial_ends_at is not None
                and _as_utc(organization.trial_ends_at) <= datetime.now(timezone.utc)
            ):
                raise HTTPException(status_code=403, detail=TRIAL_ENDED_MESSAGE)
        elif actor.role != "super_admin":
            raise HTTPException(status_code=403, detail="Target creation not allowed")

    organization_id = getattr(user, "organization_id", None)
    if actor is not None and actor.role == "admin":
        organization_id = actor.organization_id

    normalized_base_url = normalize_url(payload.base_url)
    normalized_domain = get_domain(normalized_base_url)
    if not normalized_domain:
        raise HTTPException(
            status_code=400,
            detail="base_url must be a valid http or https URL",
        )

    target = Target(
        user_id=payload.user_id,
        organization_id=organization_id,
        base_url=normalized_base_url,
        normalized_domain=normalized_domain,
    )
    session.add(target)
    await session.commit()
    await session.refresh(target)
    return target


async def list_targets(session: AsyncSession) -> list[Target]:
    result = await session.execute(select(Target).order_by(Target.id.desc()))
    return list(result.scalars().all())


async def list_targets_for_actor(session: AsyncSession, actor) -> list[Target]:
    query = select(Target).order_by(Target.id.desc())
    if actor.role != "super_admin":
        query = query.where(Target.organization_id == actor.organization_id)
    result = await session.execute(query)
    return list(result.scalars().all())


async def get_target_by_id(session: AsyncSession, target_id: int) -> Target | None:
    result = await session.execute(select(Target).where(Target.id == target_id))
    return result.scalar_one_or_none()
