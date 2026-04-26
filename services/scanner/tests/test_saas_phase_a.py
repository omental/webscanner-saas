import asyncio
from pathlib import Path
from types import SimpleNamespace

from fastapi import HTTPException

from app.api.deps import require_super_admin
from app.schemas.organization import OrganizationCreate
from app.schemas.package import PackageUpdate
from app.schemas.scan import ScanCreate
from app.schemas.user import UserCreate
from app.services.organization_service import assign_package, create_organization
from app.services.package_service import update_package
from app.services.scan_service import create_scan_for_actor, list_scans_for_actor
from app.services.target_service import list_targets_for_actor
from app.services.user_service import create_user_for_actor, list_users_for_actor


class FakeSession:
    def __init__(self) -> None:
        self.added = []
        self.commits = 0
        self.refreshed = []
        self.statements = []

    def add(self, obj) -> None:
        self.added.append(obj)

    async def commit(self) -> None:
        self.commits += 1

    async def refresh(self, obj) -> None:
        self.refreshed.append(obj)
        if getattr(obj, "id", None) is None:
            obj.id = len(self.added)

    async def execute(self, statement):
        self.statements.append(str(statement))

        class Result:
            def scalar_one_or_none(self):
                return None

            def scalars(self):
                return self

            def all(self):
                return []

        return Result()


def test_super_admin_can_create_organization() -> None:
    session = FakeSession()
    organization = asyncio.run(
        create_organization(
            session,
            OrganizationCreate(name="Acme", slug="acme", status="active"),
        )
    )

    assert organization.name == "Acme"
    assert organization.slug == "acme"
    assert session.commits == 1


def test_super_admin_can_assign_package(monkeypatch) -> None:
    session = FakeSession()
    organization = SimpleNamespace(id=1, package_id=None)

    async def fake_require_organization(_session, _organization_id):
        return organization

    async def fake_require_package(_session, _package_id):
        return SimpleNamespace(id=_package_id)

    monkeypatch.setattr(
        "app.services.organization_service.require_organization",
        fake_require_organization,
    )
    monkeypatch.setattr(
        "app.services.organization_service.require_package",
        fake_require_package,
    )

    updated = asyncio.run(assign_package(session, 1, 2))

    assert updated.package_id == 2
    assert session.commits == 1


def test_super_admin_can_update_package(monkeypatch) -> None:
    session = FakeSession()
    package = SimpleNamespace(
        id=1,
        name="Bronze",
        slug="bronze",
        scan_limit_per_week=1,
        price_monthly=0,
        status="active",
    )

    async def fake_require_package(_session, _package_id):
        return package

    monkeypatch.setattr(
        "app.services.package_service.require_package",
        fake_require_package,
    )

    updated = asyncio.run(
        update_package(
            session,
            1,
            PackageUpdate(
                name="Starter",
                slug="starter",
                scan_limit_per_week=3,
                price_monthly=9,
                status="active",
            ),
        )
    )

    assert updated.name == "Starter"
    assert updated.slug == "starter"
    assert updated.scan_limit_per_week == 3
    assert updated.price_monthly == 9
    assert session.commits == 1


def test_admin_cannot_assign_package() -> None:
    admin = SimpleNamespace(role="admin")

    try:
        asyncio.run(require_super_admin(admin))
    except HTTPException as exc:
        assert exc.status_code == 403
    else:
        raise AssertionError("Expected admin package assignment to be forbidden")


def test_admin_sees_only_own_org_users_scans_targets() -> None:
    admin = SimpleNamespace(role="admin", organization_id=7)

    for list_func, expected_table in (
        (list_users_for_actor, "users.organization_id"),
        (list_scans_for_actor, "scans.organization_id"),
        (list_targets_for_actor, "targets.organization_id"),
    ):
        session = FakeSession()
        asyncio.run(list_func(session, admin))
        assert expected_table in session.statements[0]


def test_team_member_cannot_create_scan(monkeypatch) -> None:
    session = FakeSession()
    team_member = SimpleNamespace(role="team_member", organization_id=1)

    async def fake_get_user_by_id(_session, _user_id):
        return SimpleNamespace(id=_user_id, organization_id=1)

    async def fake_get_target_by_id(_session, _target_id):
        return SimpleNamespace(id=_target_id, organization_id=1)

    monkeypatch.setattr("app.services.scan_service.get_user_by_id", fake_get_user_by_id)
    monkeypatch.setattr(
        "app.services.scan_service.get_target_by_id", fake_get_target_by_id
    )

    try:
        asyncio.run(
            create_scan_for_actor(
                session,
                ScanCreate(user_id=1, target_id=1, scan_type="full"),
                team_member,
            )
        )
    except HTTPException as exc:
        assert exc.status_code == 403
    else:
        raise AssertionError("Expected team member scan creation to be forbidden")


def test_admin_cannot_create_another_admin(monkeypatch) -> None:
    session = FakeSession()
    admin = SimpleNamespace(role="admin", organization_id=1)

    async def fake_require_organization(_session, _organization_id):
        return SimpleNamespace(id=_organization_id)

    monkeypatch.setattr(
        "app.services.user_service.require_organization", fake_require_organization
    )

    try:
        asyncio.run(
            create_user_for_actor(
                session,
                UserCreate(
                    name="Admin Two",
                    email="admin2@example.com",
                    password="password123",
                    role="admin",
                    organization_id=1,
                ),
                admin,
            )
        )
    except HTTPException as exc:
        assert exc.status_code == 403
    else:
        raise AssertionError("Expected admin creation by org admin to be forbidden")


def test_super_admin_can_create_admin(monkeypatch) -> None:
    session = FakeSession()
    super_admin = SimpleNamespace(role="super_admin", organization_id=None)

    async def fake_require_organization(_session, _organization_id):
        return SimpleNamespace(id=_organization_id)

    monkeypatch.setattr(
        "app.services.user_service.require_organization", fake_require_organization
    )

    user = asyncio.run(
        create_user_for_actor(
            session,
            UserCreate(
                name="Org Admin",
                email="org-admin@example.com",
                password="password123",
                role="admin",
                organization_id=1,
            ),
            super_admin,
        )
    )

    assert user.role == "admin"
    assert user.organization_id == 1


def test_existing_data_migration_backfill_is_defined() -> None:
    migration = Path("alembic/versions/20260425_0012_saas_phase_a.py").read_text()

    assert "Default Organization" in migration
    assert "UPDATE users" in migration
    assert "UPDATE targets" in migration
    assert "UPDATE scans" in migration
    assert "Bronze" in migration
    assert "Silver" in migration
    assert "Gold" in migration
