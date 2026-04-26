import asyncio
from types import SimpleNamespace

from fastapi import HTTPException

from app.schemas.scan import ScanCreate
from app.schemas.target import TargetCreate
from app.schemas.user import UserCreate
from app.services import scan_service, target_service
from app.services.user_service import create_user


class FakeSession:
    def __init__(self) -> None:
        self.added: list[object] = []

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def commit(self) -> None:
        return None

    async def refresh(self, obj: object) -> None:
        if getattr(obj, "id", None) is None:
            setattr(obj, "id", len(self.added))


def test_successful_user_creation_hashes_password(monkeypatch) -> None:
    async def fake_require_organization(_session: FakeSession, organization_id: int) -> object:
        return SimpleNamespace(id=organization_id)

    monkeypatch.setattr(
        "app.services.user_service.require_organization", fake_require_organization
    )

    session = FakeSession()
    payload = UserCreate(
        name="Muba",
        email="muba@example.com",
        password="super-secret",
        role="admin",
        organization_id=1,
        status="active",
    )

    user = asyncio.run(create_user(session, payload))

    assert user.name == "Muba"
    assert user.password_hash != "super-secret"
    assert "super-secret" not in user.password_hash
    assert user.password_hash.startswith(("$2a$", "$2b$", "$2y$"))


def test_successful_target_creation_derives_normalized_domain(monkeypatch) -> None:
    async def fake_get_user_by_id(session: FakeSession, user_id: int) -> object:
        return SimpleNamespace(id=user_id)

    monkeypatch.setattr(target_service, "get_user_by_id", fake_get_user_by_id)

    session = FakeSession()
    payload = TargetCreate(user_id=1, base_url="HTTPS://Example.COM/app/")

    target = asyncio.run(target_service.create_target(session, payload))

    assert target.user_id == 1
    assert target.base_url == "https://example.com/app"
    assert target.normalized_domain == "example.com"


def test_scan_creation_with_missing_user_returns_clean_error(monkeypatch) -> None:
    async def fake_get_user_by_id(session: FakeSession, user_id: int) -> None:
        return None

    monkeypatch.setattr(scan_service, "get_user_by_id", fake_get_user_by_id)

    session = FakeSession()
    payload = ScanCreate(user_id=999, target_id=1, scan_type="full")

    try:
        asyncio.run(scan_service.create_scan(session, payload))
    except HTTPException as exc:
        assert exc.status_code == 404
        assert exc.detail == "User not found"
    else:
        raise AssertionError("Expected HTTPException for missing user")


def test_scan_creation_with_missing_target_returns_clean_error(monkeypatch) -> None:
    async def fake_get_user_by_id(session: FakeSession, user_id: int) -> object:
        return SimpleNamespace(id=user_id)

    async def fake_get_target_by_id(session: FakeSession, target_id: int) -> None:
        return None

    monkeypatch.setattr(scan_service, "get_user_by_id", fake_get_user_by_id)
    monkeypatch.setattr(scan_service, "get_target_by_id", fake_get_target_by_id)

    session = FakeSession()
    payload = ScanCreate(user_id=1, target_id=999, scan_type="full")

    try:
        asyncio.run(scan_service.create_scan(session, payload))
    except HTTPException as exc:
        assert exc.status_code == 404
        assert exc.detail == "Target not found"
    else:
        raise AssertionError("Expected HTTPException for missing target")
