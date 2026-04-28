from typing import Annotated

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    get_db_session,
    require_admin_or_super_admin,
    require_authenticated_user,
)
from app.models.scheduled_scan import ScheduledScan
from app.models.user import User
from app.schemas.scheduled_scan import (
    ScheduledScanCreate,
    ScheduledScanRead,
    ScheduledScanUpdate,
)
from app.services.scheduled_scan_service import (
    create_scheduled_scan_for_actor,
    disable_scheduled_scan_for_actor,
    list_scheduled_scans_for_actor,
    require_scheduled_scan_access,
    update_scheduled_scan_for_actor,
)

router = APIRouter(prefix="/scheduled-scans", tags=["scheduled-scans"])
DbSession = Annotated[AsyncSession, Depends(get_db_session)]
CurrentUser = Annotated[User, Depends(require_authenticated_user)]
AdminUser = Annotated[User, Depends(require_admin_or_super_admin)]


def _serialize_scheduled_scan(schedule: ScheduledScan) -> ScheduledScanRead:
    return ScheduledScanRead.model_validate(
        {
            "id": schedule.id,
            "organization_id": schedule.organization_id,
            "target_id": schedule.target_id,
            "created_by_user_id": schedule.created_by_user_id,
            "scan_profile": schedule.scan_profile or "standard",
            "frequency": schedule.frequency,
            "next_run_at": schedule.next_run_at,
            "last_run_at": schedule.last_run_at,
            "is_active": schedule.is_active,
            "created_at": schedule.created_at,
            "updated_at": schedule.updated_at,
        }
    )


@router.post("", response_model=ScheduledScanRead, status_code=status.HTTP_201_CREATED)
async def create_scheduled_scan_endpoint(
    payload: ScheduledScanCreate,
    session: DbSession,
    admin: AdminUser,
) -> ScheduledScanRead:
    schedule = await create_scheduled_scan_for_actor(session, payload, admin)
    return _serialize_scheduled_scan(schedule)


@router.get("", response_model=list[ScheduledScanRead])
async def list_scheduled_scans_endpoint(
    session: DbSession,
    current_user: CurrentUser,
) -> list[ScheduledScanRead]:
    schedules = await list_scheduled_scans_for_actor(session, current_user)
    return [_serialize_scheduled_scan(schedule) for schedule in schedules]


@router.get("/{scheduled_scan_id}", response_model=ScheduledScanRead)
async def get_scheduled_scan_endpoint(
    scheduled_scan_id: int,
    session: DbSession,
    current_user: CurrentUser,
) -> ScheduledScanRead:
    schedule = await require_scheduled_scan_access(
        session, scheduled_scan_id, current_user
    )
    return _serialize_scheduled_scan(schedule)


@router.patch("/{scheduled_scan_id}", response_model=ScheduledScanRead)
async def update_scheduled_scan_endpoint(
    scheduled_scan_id: int,
    payload: ScheduledScanUpdate,
    session: DbSession,
    admin: AdminUser,
) -> ScheduledScanRead:
    schedule = await update_scheduled_scan_for_actor(
        session, scheduled_scan_id, payload, admin
    )
    return _serialize_scheduled_scan(schedule)


@router.post("/{scheduled_scan_id}/disable", response_model=ScheduledScanRead)
async def disable_scheduled_scan_endpoint(
    scheduled_scan_id: int,
    session: DbSession,
    admin: AdminUser,
) -> ScheduledScanRead:
    schedule = await disable_scheduled_scan_for_actor(
        session, scheduled_scan_id, admin
    )
    return _serialize_scheduled_scan(schedule)
