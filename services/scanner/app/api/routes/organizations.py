from typing import Annotated

from fastapi import APIRouter, Depends, status
from sqlalchemy import inspect
from sqlalchemy.exc import NoInspectionAvailable
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db_session, require_super_admin
from app.models.organization import Organization
from app.models.user import User
from app.schemas.organization import (
    OrganizationCreate,
    OrganizationPackageUpdate,
    OrganizationRead,
    OrganizationSubscriptionUpdate,
    OrganizationTrialStart,
    OrganizationUpdate,
)
from app.services.organization_service import (
    assign_package,
    create_organization,
    list_organizations,
    require_organization,
    update_organization,
)
from app.services.subscription_service import start_trial, update_subscription

router = APIRouter(prefix="/organizations", tags=["organizations"])
DbSession = Annotated[AsyncSession, Depends(get_db_session)]
SuperAdmin = Annotated[User, Depends(require_super_admin)]


def _serialize_organization(organization: Organization) -> OrganizationRead:
    try:
        package_loaded = "package" not in inspect(organization).unloaded
    except NoInspectionAvailable:
        package_loaded = hasattr(organization, "package")
    package = organization.package if package_loaded else None
    return OrganizationRead.model_validate(
        {
            "id": organization.id,
            "name": organization.name,
            "slug": organization.slug,
            "package_id": organization.package_id,
            "package_name": package.name if package else None,
            "status": organization.status,
            "subscription_status": organization.subscription_status,
            "subscription_start": organization.subscription_start,
            "subscription_end": organization.subscription_end,
            "trial_ends_at": organization.trial_ends_at,
            "created_at": organization.created_at,
            "updated_at": organization.updated_at,
        }
    )


@router.get("", response_model=list[OrganizationRead])
async def list_organizations_endpoint(
    session: DbSession, _super_admin: SuperAdmin
) -> list[OrganizationRead]:
    organizations = await list_organizations(session)
    return [_serialize_organization(organization) for organization in organizations]


@router.post("", response_model=OrganizationRead, status_code=status.HTTP_201_CREATED)
async def create_organization_endpoint(
    payload: OrganizationCreate, session: DbSession, _super_admin: SuperAdmin
) -> OrganizationRead:
    organization = await create_organization(session, payload)
    return _serialize_organization(organization)


@router.patch("/{organization_id}", response_model=OrganizationRead)
async def update_organization_endpoint(
    organization_id: int,
    payload: OrganizationUpdate,
    session: DbSession,
    _super_admin: SuperAdmin,
) -> OrganizationRead:
    organization = await update_organization(session, organization_id, payload)
    return _serialize_organization(organization)


@router.patch("/{organization_id}/package", response_model=OrganizationRead)
async def assign_package_endpoint(
    organization_id: int,
    payload: OrganizationPackageUpdate,
    session: DbSession,
    _super_admin: SuperAdmin,
) -> OrganizationRead:
    organization = await assign_package(session, organization_id, payload.package_id)
    return _serialize_organization(organization)


@router.patch("/{organization_id}/subscription", response_model=OrganizationRead)
async def update_subscription_endpoint(
    organization_id: int,
    payload: OrganizationSubscriptionUpdate,
    session: DbSession,
    _super_admin: SuperAdmin,
) -> OrganizationRead:
    organization = await require_organization(session, organization_id)
    organization = await update_subscription(session, organization, payload)
    return _serialize_organization(organization)


@router.post("/{organization_id}/start-trial", response_model=OrganizationRead)
async def start_trial_endpoint(
    organization_id: int,
    payload: OrganizationTrialStart,
    session: DbSession,
    _super_admin: SuperAdmin,
) -> OrganizationRead:
    organization = await require_organization(session, organization_id)
    organization = await start_trial(session, organization, payload.days)
    return _serialize_organization(organization)
