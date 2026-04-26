from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.organization import Organization
from app.schemas.organization import OrganizationCreate, OrganizationUpdate
from app.services.package_service import require_package


async def create_organization(
    session: AsyncSession, payload: OrganizationCreate
) -> Organization:
    if payload.package_id is not None:
        await require_package(session, payload.package_id)

    organization = Organization(
        name=payload.name,
        slug=payload.slug.lower().strip(),
        package_id=payload.package_id,
        status=payload.status,
    )
    session.add(organization)
    await session.commit()
    await session.refresh(organization)
    return organization


async def list_organizations(session: AsyncSession) -> list[Organization]:
    result = await session.execute(
        select(Organization)
        .options(selectinload(Organization.package))
        .order_by(Organization.id.desc())
    )
    return list(result.scalars().all())


async def get_organization_by_id(
    session: AsyncSession, organization_id: int
) -> Organization | None:
    result = await session.execute(
        select(Organization)
        .options(selectinload(Organization.package))
        .where(Organization.id == organization_id)
    )
    return result.scalar_one_or_none()


async def require_organization(
    session: AsyncSession, organization_id: int
) -> Organization:
    organization = await get_organization_by_id(session, organization_id)
    if organization is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    return organization


async def update_organization(
    session: AsyncSession, organization_id: int, payload: OrganizationUpdate
) -> Organization:
    organization = await require_organization(session, organization_id)
    updates = payload.model_dump(exclude_unset=True)
    if "name" in updates and updates["name"] is not None:
        organization.name = updates["name"]
    if "slug" in updates and updates["slug"] is not None:
        organization.slug = updates["slug"].lower().strip()
    if "status" in updates and updates["status"] is not None:
        organization.status = updates["status"]
    await session.commit()
    await session.refresh(organization)
    return organization


async def assign_package(
    session: AsyncSession, organization_id: int, package_id: int | None
) -> Organization:
    organization = await require_organization(session, organization_id)
    if package_id is not None:
        await require_package(session, package_id)
    organization.package_id = package_id
    await session.commit()
    await session.refresh(organization)
    return organization
