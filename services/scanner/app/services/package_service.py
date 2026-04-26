from decimal import Decimal

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.package import Package
from app.schemas.package import PackageUpdate

DEFAULT_PACKAGES = (
    ("Bronze", "bronze", 1, Decimal("0.00")),
    ("Silver", "silver", 10, Decimal("0.00")),
    ("Gold", "gold", 100, Decimal("0.00")),
)


async def ensure_default_packages(session: AsyncSession) -> None:
    for name, slug, limit, price in DEFAULT_PACKAGES:
        result = await session.execute(select(Package).where(Package.slug == slug))
        if result.scalar_one_or_none() is None:
            session.add(
                Package(
                    name=name,
                    slug=slug,
                    scan_limit_per_week=limit,
                    price_monthly=price,
                    status="active",
                )
            )
    await session.commit()


async def list_packages(session: AsyncSession) -> list[Package]:
    await ensure_default_packages(session)
    result = await session.execute(select(Package).order_by(Package.id.asc()))
    return list(result.scalars().all())


async def get_package_by_id(session: AsyncSession, package_id: int) -> Package | None:
    result = await session.execute(select(Package).where(Package.id == package_id))
    return result.scalar_one_or_none()


async def require_package(session: AsyncSession, package_id: int) -> Package:
    package = await get_package_by_id(session, package_id)
    if package is None:
        raise HTTPException(status_code=404, detail="Package not found")
    return package


async def update_package(
    session: AsyncSession, package_id: int, payload: PackageUpdate
) -> Package:
    package = await require_package(session, package_id)
    updates = payload.model_dump(exclude_unset=True)
    if "name" in updates and updates["name"] is not None:
        package.name = updates["name"].strip()
    if "slug" in updates and updates["slug"] is not None:
        package.slug = updates["slug"].lower().strip()
    if (
        "scan_limit_per_week" in updates
        and updates["scan_limit_per_week"] is not None
    ):
        package.scan_limit_per_week = updates["scan_limit_per_week"]
    if "price_monthly" in updates and updates["price_monthly"] is not None:
        package.price_monthly = updates["price_monthly"]
    if "status" in updates and updates["status"] is not None:
        package.status = updates["status"]
    await session.commit()
    await session.refresh(package)
    return package
