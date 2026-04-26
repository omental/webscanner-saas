from typing import Annotated

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import inspect
from sqlalchemy.exc import NoInspectionAvailable
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db_session, require_admin_or_super_admin
from app.models.user import User
from app.schemas.user import UserCreate, UserRead, UserUpdate
from app.services.user_service import (
    create_user_for_actor,
    delete_user_for_actor,
    list_users_for_actor,
    update_user_for_actor,
)

router = APIRouter(prefix="/users", tags=["users"])
DbSession = Annotated[AsyncSession, Depends(get_db_session)]
AdminUser = Annotated[User, Depends(require_admin_or_super_admin)]


def _serialize_user(user: User) -> UserRead:
    try:
        organization_loaded = "organization" not in inspect(user).unloaded
    except NoInspectionAvailable:
        organization_loaded = hasattr(user, "organization")
    organization = user.organization if organization_loaded else None
    return UserRead.model_validate(
        {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "role": user.role,
            "organization_id": getattr(user, "organization_id", None),
            "organization_name": organization.name if organization else None,
            "status": user.status,
            "created_at": user.created_at,
            "updated_at": user.updated_at,
        }
    )


@router.post("", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def create_user_endpoint(
    payload: UserCreate, session: DbSession, admin: AdminUser
) -> UserRead:
    user = await create_user_for_actor(session, payload, admin)
    return _serialize_user(user)


@router.get("", response_model=list[UserRead])
async def list_users_endpoint(session: DbSession, admin: AdminUser) -> list[UserRead]:
    users = await list_users_for_actor(session, admin)
    return [_serialize_user(user) for user in users]


@router.patch("/{user_id}", response_model=UserRead)
async def update_user_endpoint(
    user_id: int, payload: UserUpdate, session: DbSession, admin: AdminUser
) -> UserRead:
    user = await update_user_for_actor(session, user_id, payload, admin)
    return _serialize_user(user)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user_endpoint(
    user_id: int, session: DbSession, admin: AdminUser
) -> Response:
    await delete_user_for_actor(session, user_id, admin)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
