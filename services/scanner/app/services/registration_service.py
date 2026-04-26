import re
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.organization import Organization
from app.models.package import Package
from app.models.user import User
from app.schemas.registration import TrialRegistrationCreate, TrialRegistrationRead
from app.services.invoice_service import (
    create_billing_record_for_trial_registration,
    create_invoice_for_billing_record,
)
from app.services.package_service import ensure_default_packages
from app.services.user_service import get_user_by_email, hash_password


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "organization"


async def _unique_org_slug(session: AsyncSession, name: str) -> str:
    base = _slugify(name)
    slug = base
    suffix = 2
    while True:
        result = await session.execute(select(Organization).where(Organization.slug == slug))
        if result.scalar_one_or_none() is None:
            return slug
        slug = f"{base}-{suffix}"
        suffix += 1


async def _select_package(
    session: AsyncSession, payload: TrialRegistrationCreate
) -> Package:
    await ensure_default_packages(session)
    if payload.selected_package_id is not None:
        result = await session.execute(
            select(Package).where(Package.id == payload.selected_package_id)
        )
    else:
        result = await session.execute(
            select(Package).where(Package.slug == payload.selected_package_slug)
        )
    package = result.scalar_one_or_none()
    if package is None or package.status != "active":
        raise HTTPException(status_code=404, detail="Package not found")
    return package


async def register_trial_admin(
    session: AsyncSession, payload: TrialRegistrationCreate
) -> TrialRegistrationRead:
    if await get_user_by_email(session, str(payload.email)):
        raise HTTPException(status_code=400, detail="Email is already registered")

    package = await _select_package(session, payload)
    now = datetime.now(timezone.utc)
    trial_ends_at = now + timedelta(days=14)
    organization = Organization(
        name=payload.organization_name,
        slug=await _unique_org_slug(session, payload.organization_name),
        package_id=package.id,
        status="active",
        subscription_status="trial",
        subscription_start=now,
        subscription_end=trial_ends_at,
        trial_ends_at=trial_ends_at,
    )
    session.add(organization)
    await session.flush()

    user = User(
        name=payload.name,
        email=str(payload.email).lower().strip(),
        password_hash=hash_password(payload.password),
        organization_id=organization.id,
        role="admin",
        status="active",
    )
    session.add(user)
    await session.flush()

    billing_record = await create_billing_record_for_trial_registration(
        session, organization, package, trial_ends_at
    )
    invoice = await create_invoice_for_billing_record(
        session,
        billing_record,
        organization,
        issued_at=now,
        due_date=trial_ends_at,
    )
    await session.commit()
    await session.refresh(invoice)

    return TrialRegistrationRead(
        success=True,
        message="Your 14-day free trial has started.",
        trial_ends_at=trial_ends_at,
        invoice_id=invoice.id,
        invoice_pdf_url=invoice.pdf_url or f"/api/v1/invoices/{invoice.id}/download",
    )
