import asyncio
import hashlib
import secrets
from datetime import datetime, timezone
from types import SimpleNamespace

from fastapi import HTTPException
from passlib.hash import bcrypt

from app.api.routes.auth import _serialize_user
from app.services import user_service
from app.services.user_service import authenticate_user, hash_password


class FakeSession:
    def __init__(self) -> None:
        self.commit_count = 0
        self.refresh_count = 0

    async def commit(self) -> None:
        self.commit_count += 1

    async def refresh(self, _obj) -> None:
        self.refresh_count += 1


def make_user(
    *,
    password: str = "correct-password",
    password_hash: str | None = None,
    status: str = "active",
) -> SimpleNamespace:
    now = datetime.now(timezone.utc)
    return SimpleNamespace(
        id=1,
        name="Admin User",
        email="admin@example.com",
        password_hash=password_hash or hash_password(password),
        role="admin",
        status=status,
        created_at=now,
        updated_at=now,
    )


def make_legacy_pbkdf2_hash(password: str) -> str:
    salt = secrets.token_hex(16)
    iterations = 100_000
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations
    ).hex()
    return f"pbkdf2_sha256${iterations}${salt}${digest}"


def test_bcrypt_user_can_login(monkeypatch) -> None:
    user = make_user(password_hash=bcrypt.hash("correct-password"))
    session = FakeSession()

    async def fake_get_user_by_email(_session, _email):
        return user

    monkeypatch.setattr(user_service, "get_user_by_email", fake_get_user_by_email)

    authenticated = asyncio.run(
        authenticate_user(session, "admin@example.com", "correct-password")
    )

    assert authenticated.id == 1
    assert authenticated.role == "admin"
    assert authenticated.status == "active"
    assert session.commit_count == 0


def test_pbkdf2_user_can_login(monkeypatch) -> None:
    user = make_user(password_hash=make_legacy_pbkdf2_hash("correct-password"))
    session = FakeSession()

    async def fake_get_user_by_email(_session, _email):
        return user

    monkeypatch.setattr(user_service, "get_user_by_email", fake_get_user_by_email)

    authenticated = asyncio.run(
        authenticate_user(session, "admin@example.com", "correct-password")
    )

    assert authenticated.id == 1
    assert authenticated.role == "admin"
    assert authenticated.status == "active"


def test_pbkdf2_user_hash_auto_upgrades_to_bcrypt(monkeypatch) -> None:
    user = make_user(password_hash=make_legacy_pbkdf2_hash("correct-password"))
    session = FakeSession()
    original_hash = user.password_hash

    async def fake_get_user_by_email(_session, _email):
        return user

    monkeypatch.setattr(user_service, "get_user_by_email", fake_get_user_by_email)

    asyncio.run(authenticate_user(session, "admin@example.com", "correct-password"))

    assert user.password_hash != original_hash
    assert user.password_hash.startswith(("$2a$", "$2b$", "$2y$"))
    assert bcrypt.verify("correct-password", user.password_hash)
    assert session.commit_count == 1
    assert session.refresh_count == 1


def test_wrong_password_fails(monkeypatch) -> None:
    user = make_user()

    async def fake_get_user_by_email(_session, _email):
        return user

    monkeypatch.setattr(user_service, "get_user_by_email", fake_get_user_by_email)

    try:
        asyncio.run(
            authenticate_user(SimpleNamespace(), "admin@example.com", "wrong-password")
        )
    except HTTPException as exc:
        assert exc.status_code == 401
        assert exc.detail == "Invalid email or password"
    else:
        raise AssertionError("Expected wrong password to fail")


def test_inactive_user_fails(monkeypatch) -> None:
    user = make_user(status="inactive")

    async def fake_get_user_by_email(_session, _email):
        return user

    monkeypatch.setattr(user_service, "get_user_by_email", fake_get_user_by_email)

    try:
        asyncio.run(
            authenticate_user(SimpleNamespace(), "admin@example.com", "correct-password")
        )
    except HTTPException as exc:
        assert exc.status_code == 403
        assert exc.detail == "User account is inactive"
    else:
        raise AssertionError("Expected inactive user to fail")


def test_login_response_does_not_include_password_hash() -> None:
    serialized = _serialize_user(make_user())
    payload = serialized.model_dump()

    assert payload["email"] == "admin@example.com"
    assert payload["role"] == "admin"
    assert "password_hash" not in payload
