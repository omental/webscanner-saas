import argparse
import asyncio

from sqlalchemy import select

from app.db.session import AsyncSessionLocal
from app.models.user import User
from app.services.user_service import hash_password


async def create_or_update_super_admin(email: str, password: str, name: str) -> User:
    async with AsyncSessionLocal() as session:
        normalized_email = email.lower().strip()
        result = await session.execute(select(User).where(User.email == normalized_email))
        user = result.scalar_one_or_none()
        if user is None:
            user = User(
                name=name,
                email=normalized_email,
                password_hash=hash_password(password),
                organization_id=None,
                role="super_admin",
                status="active",
            )
            session.add(user)
        else:
            user.name = name
            user.password_hash = hash_password(password)
            user.organization_id = None
            user.role = "super_admin"
            user.status = "active"

        await session.commit()
        await session.refresh(user)
        return user


def main() -> None:
    parser = argparse.ArgumentParser(description="Create or update a super admin.")
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--name", required=True)
    args = parser.parse_args()

    user = asyncio.run(
        create_or_update_super_admin(args.email, args.password, args.name)
    )
    print(f"Super admin ready: {user.email}")


if __name__ == "__main__":
    main()
