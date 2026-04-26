from collections.abc import AsyncGenerator
from typing import Annotated

from fastapi import Depends, Header, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import AsyncSessionLocal
from app.models.user import User
from app.services.user_service import get_user_by_id


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session


DbSession = Annotated[AsyncSession, Depends(get_db_session)]


async def get_current_user(
    session: DbSession,
    x_current_user_id: Annotated[int | None, Header(alias="X-Current-User-Id")] = None,
) -> User | None:
    if x_current_user_id is None:
        return None

    user = await get_user_by_id(session, x_current_user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="Current user not found")
    if user.status != "active":
        raise HTTPException(status_code=403, detail="Current user is inactive")
    return user


async def require_admin(
    current_user: Annotated[User | None, Depends(get_current_user)]
) -> User:
    if current_user is None:
        raise HTTPException(status_code=401, detail="Current user required")
    if current_user.role not in {"admin", "super_admin"}:
        raise HTTPException(status_code=403, detail="Admin role required")
    return current_user


async def require_authenticated_user(
    current_user: Annotated[User | None, Depends(get_current_user)]
) -> User:
    if current_user is None:
        raise HTTPException(status_code=401, detail="Current user required")
    return current_user


async def require_super_admin(
    current_user: Annotated[User | None, Depends(get_current_user)]
) -> User:
    if current_user is None:
        raise HTTPException(status_code=401, detail="Current user required")
    if current_user.role != "super_admin":
        raise HTTPException(status_code=403, detail="Super admin role required")
    return current_user


async def require_admin_or_super_admin(
    current_user: Annotated[User | None, Depends(get_current_user)]
) -> User:
    if current_user is None:
        raise HTTPException(status_code=401, detail="Current user required")
    if current_user.role not in {"admin", "super_admin"}:
        raise HTTPException(status_code=403, detail="Admin role required")
    return current_user


async def require_org_admin(
    current_user: Annotated[User | None, Depends(get_current_user)]
) -> User:
    if current_user is None:
        raise HTTPException(status_code=401, detail="Current user required")
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Organization admin role required")
    if current_user.organization_id is None:
        raise HTTPException(status_code=403, detail="Organization required")
    return current_user
