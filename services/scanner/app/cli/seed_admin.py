import asyncio
import os

from app.db.session import AsyncSessionLocal
from app.models.user import User
from app.services.user_service import get_user_by_email, hash_password


async def seed_admin() -> None:
    email = os.environ.get("ADMIN_EMAIL", "admin@example.com")
    password = os.environ.get("ADMIN_PASSWORD", "admin-password")
    name = os.environ.get("ADMIN_NAME", "Admin User")

    async with AsyncSessionLocal() as session:
        existing = await get_user_by_email(session, email)
        if existing is not None:
            existing.role = "super_admin"
            existing.organization_id = None
            existing.status = "active"
            existing.password_hash = hash_password(password)
            await session.commit()
            print(f"Updated super admin: {existing.email}")
            return

        user = User(
            name=name,
            email=email.lower().strip(),
            password_hash=hash_password(password),
            organization_id=None,
            role="super_admin",
            status="active",
        )
        session.add(user)
        await session.commit()
        print(f"Created super admin user: {user.email}")


if __name__ == "__main__":
    asyncio.run(seed_admin())
