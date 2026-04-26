import secrets

from fastapi import HTTPException
from passlib.crypto.digest import pbkdf2_hmac
from passlib.hash import bcrypt, django_pbkdf2_sha256
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.user import User
from app.schemas.user import UserCreate, UserUpdate
from app.services.organization_service import require_organization

PBKDF2_SHA256_PREFIX = "pbkdf2_sha256"


def detect_password_hash_type(password_hash: str) -> str:
    if bcrypt.identify(password_hash):
        return "bcrypt"
    if password_hash.startswith(PBKDF2_SHA256_PREFIX):
        return "pbkdf2_sha256"
    return "unknown"


def hash_password(password: str) -> str:
    return bcrypt.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    hash_type = detect_password_hash_type(password_hash)
    if hash_type == "bcrypt":
        return bool(bcrypt.verify(password, password_hash))
    if hash_type == "pbkdf2_sha256":
        return verify_pbkdf2_sha256_password(password, password_hash)
    return False


def verify_pbkdf2_sha256_password(password: str, password_hash: str) -> bool:
    try:
        if django_pbkdf2_sha256.verify(password, password_hash):
            return True
    except (TypeError, ValueError):
        pass

    try:
        scheme, iterations_value, salt, expected_digest = password_hash.split("$", 3)
        iterations = int(iterations_value)
    except ValueError:
        return False

    if scheme != "pbkdf2_sha256":
        return False

    digest = pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations
    ).hex()
    return secrets.compare_digest(digest, expected_digest)


async def create_user(session: AsyncSession, payload: UserCreate) -> User:
    return await create_user_for_actor(session, payload, actor=None)


async def create_user_for_actor(
    session: AsyncSession, payload: UserCreate, actor: User | None
) -> User:
    organization_id = payload.organization_id
    if actor is not None:
        if actor.role == "admin":
            if payload.role != "team_member":
                raise HTTPException(
                    status_code=403,
                    detail="Admins can only create team members",
                )
            organization_id = actor.organization_id
        elif actor.role != "super_admin":
            raise HTTPException(status_code=403, detail="User management not allowed")

    if payload.role == "super_admin":
        organization_id = None
        if actor is not None and actor.role != "super_admin":
            raise HTTPException(status_code=403, detail="Super admin role required")
    elif organization_id is None:
        raise HTTPException(status_code=400, detail="Organization is required")

    if organization_id is not None:
        await require_organization(session, organization_id)

    user = User(
        name=payload.name,
        email=str(payload.email).lower().strip(),
        password_hash=hash_password(payload.password),
        organization_id=organization_id,
        role=payload.role,
        status=payload.status,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


async def list_users(session: AsyncSession) -> list[User]:
    result = await session.execute(
        select(User).options(selectinload(User.organization)).order_by(User.id.desc())
    )
    return list(result.scalars().all())


async def list_users_for_actor(session: AsyncSession, actor: User) -> list[User]:
    query = select(User).options(selectinload(User.organization)).order_by(User.id.desc())
    if actor.role != "super_admin":
        query = query.where(User.organization_id == actor.organization_id)
    result = await session.execute(query)
    return list(result.scalars().all())


async def get_user_by_id(session: AsyncSession, user_id: int) -> User | None:
    result = await session.execute(
        select(User).options(selectinload(User.organization)).where(User.id == user_id)
    )
    return result.scalar_one_or_none()


async def get_user_by_email(session: AsyncSession, email: str) -> User | None:
    result = await session.execute(
        select(User)
        .options(selectinload(User.organization))
        .where(User.email == email.lower().strip())
    )
    return result.scalar_one_or_none()


async def authenticate_user(
    session: AsyncSession, email: str, password: str
) -> User:
    user = await get_user_by_email(session, email)
    if user is None or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if user.status != "active":
        raise HTTPException(status_code=403, detail="User account is inactive")
    if detect_password_hash_type(user.password_hash) == "pbkdf2_sha256":
        user.password_hash = hash_password(password)
        await session.commit()
        await session.refresh(user)
    return user


async def update_user(
    session: AsyncSession, user_id: int, payload: UserUpdate
) -> User:
    return await update_user_for_actor(session, user_id, payload, actor=None)


async def update_user_for_actor(
    session: AsyncSession, user_id: int, payload: UserUpdate, actor: User | None
) -> User:
    user = await get_user_by_id(session, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    updates = payload.model_dump(exclude_unset=True)
    next_role = updates.get("role", user.role)
    next_status = updates.get("status", user.status)
    if user.role == "super_admin" and (
        next_role != "super_admin" or next_status != "active"
    ):
        await ensure_not_last_active_super_admin(session, user.id)
    if actor is not None:
        if actor.role == "admin":
            if user.organization_id != actor.organization_id:
                raise HTTPException(status_code=404, detail="User not found")
            if user.role != "team_member":
                raise HTTPException(
                    status_code=403,
                    detail="Admins can only manage team members",
                )
            if updates.get("role") not in {None, "team_member"}:
                raise HTTPException(
                    status_code=403,
                    detail="Admins cannot assign admin roles",
                )
            updates["organization_id"] = actor.organization_id
        elif actor.role != "super_admin":
            raise HTTPException(status_code=403, detail="User management not allowed")

    if "email" in updates and updates["email"] is not None:
        user.email = str(updates["email"]).lower().strip()
    if "name" in updates and updates["name"] is not None:
        user.name = updates["name"]
    if "role" in updates and updates["role"] is not None:
        if updates["role"] == "super_admin":
            user.organization_id = None
        user.role = updates["role"]
    if "organization_id" in updates:
        if user.role == "super_admin":
            user.organization_id = None
        elif updates["organization_id"] is None:
            raise HTTPException(status_code=400, detail="Organization is required")
        else:
            await require_organization(session, updates["organization_id"])
            user.organization_id = updates["organization_id"]
    if "status" in updates and updates["status"] is not None:
        user.status = updates["status"]
    if "password" in updates and updates["password"]:
        user.password_hash = hash_password(updates["password"])

    await session.commit()
    await session.refresh(user)
    return user


async def delete_user(session: AsyncSession, user_id: int) -> None:
    await delete_user_for_actor(session, user_id, actor=None)


async def delete_user_for_actor(
    session: AsyncSession, user_id: int, actor: User | None
) -> None:
    user = await get_user_by_id(session, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.role == "super_admin":
        await ensure_not_last_active_super_admin(session, user.id)

    if actor is not None:
        if actor.role == "admin":
            if user.organization_id != actor.organization_id or user.role != "team_member":
                raise HTTPException(
                    status_code=403,
                    detail="Admins can only delete team members",
                )
        elif actor.role != "super_admin":
            raise HTTPException(status_code=403, detail="User management not allowed")

    await session.delete(user)
    await session.commit()


async def ensure_not_last_active_super_admin(
    session: AsyncSession, user_id: int
) -> None:
    result = await session.execute(
        select(func.count(User.id)).where(
            User.role == "super_admin",
            User.status == "active",
            User.id != user_id,
        )
    )
    if result.scalar_one() == 0:
        raise HTTPException(
            status_code=400,
            detail="At least one active super admin is required",
        )
