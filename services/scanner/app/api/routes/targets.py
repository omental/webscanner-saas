from typing import Annotated

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    get_db_session,
    require_admin_or_super_admin,
    require_authenticated_user,
)
from app.models.user import User
from app.models.target import Target
from app.schemas.target import TargetCreate, TargetRead
from app.services.target_service import create_target_for_actor, list_targets_for_actor

router = APIRouter(prefix="/targets", tags=["targets"])
DbSession = Annotated[AsyncSession, Depends(get_db_session)]
CurrentUser = Annotated[User, Depends(require_authenticated_user)]
AdminUser = Annotated[User, Depends(require_admin_or_super_admin)]


def _serialize_target(target: Target) -> TargetRead:
    return TargetRead.model_validate(
        {
            "id": target.id,
            "user_id": target.user_id,
            "organization_id": target.organization_id,
            "base_url": target.base_url,
            "normalized_domain": target.normalized_domain,
            "created_at": target.created_at,
            "updated_at": target.updated_at,
        }
    )


@router.post("", response_model=TargetRead, status_code=status.HTTP_201_CREATED)
async def create_target_endpoint(
    payload: TargetCreate, session: DbSession, admin: AdminUser
) -> TargetRead:
    target = await create_target_for_actor(session, payload, admin)
    return _serialize_target(target)


@router.get("", response_model=list[TargetRead])
async def list_targets_endpoint(session: DbSession, current_user: CurrentUser) -> list[TargetRead]:
    targets = await list_targets_for_actor(session, current_user)
    return [_serialize_target(target) for target in targets]
