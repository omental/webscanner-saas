from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import inspect
from sqlalchemy.exc import NoInspectionAvailable
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db_session
from app.models.user import User
from app.schemas.registration import TrialRegistrationCreate, TrialRegistrationRead
from app.schemas.user import UserLogin, UserRead
from app.services.registration_service import register_trial_admin
from app.services.user_service import authenticate_user

router = APIRouter(prefix="/auth", tags=["auth"])
DbSession = Annotated[AsyncSession, Depends(get_db_session)]


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


@router.post("/login", response_model=UserRead)
async def login_endpoint(payload: UserLogin, session: DbSession) -> UserRead:
    user = await authenticate_user(session, payload.email, payload.password)
    return _serialize_user(user)


@router.post("/register", response_model=TrialRegistrationRead)
async def register_endpoint(
    payload: TrialRegistrationCreate, session: DbSession
) -> TrialRegistrationRead:
    return await register_trial_admin(session, payload)
