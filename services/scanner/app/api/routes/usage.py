from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    get_db_session,
    require_authenticated_user,
    require_super_admin,
)
from app.models.user import User
from app.schemas.usage import UsageRead
from app.services.usage_service import (
    get_usage_for_organization_id,
    list_organization_usage,
)

router = APIRouter(prefix="/usage", tags=["usage"])
DbSession = Annotated[AsyncSession, Depends(get_db_session)]
CurrentUser = Annotated[User, Depends(require_authenticated_user)]
SuperAdmin = Annotated[User, Depends(require_super_admin)]


@router.get("/me", response_model=UsageRead)
async def get_my_usage_endpoint(
    session: DbSession, current_user: CurrentUser
) -> UsageRead:
    if current_user.organization_id is None:
        raise HTTPException(status_code=400, detail="Organization required")
    return await get_usage_for_organization_id(session, current_user.organization_id)


@router.get("/organizations", response_model=list[UsageRead])
async def list_organization_usage_endpoint(
    session: DbSession, _super_admin: SuperAdmin
) -> list[UsageRead]:
    return await list_organization_usage(session)
