import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from fastapi import HTTPException

from app.api.deps import require_super_admin
from app.api.routes.payment_methods import _serialize_payment_method
from app.api.routes.webhooks import _handle_webhook
from app.models.organization import Organization
from app.models.payment_method import PaymentMethod
from app.schemas.organization import OrganizationSubscriptionUpdate
from app.schemas.payment_method import PaymentMethodUpdate
from app.schemas.scan import ScanCreate
from app.schemas.target import TargetCreate
from app.services.payment_method_service import (
    ensure_default_payment_methods,
    get_enabled_webhook_method,
    list_payment_methods,
    update_payment_method,
)
from app.services.scan_service import create_scan_for_actor
from app.services.subscription_service import (
    EXPIRED_MESSAGE,
    SUSPENDED_MESSAGE,
    TRIAL_ENDED_MESSAGE,
    check_org_subscription,
    update_subscription,
)
from app.services.target_service import create_target_for_actor


class FakeSession:
    def __init__(self, rows=None) -> None:
        self.rows = rows or []
        self.added = []
        self.commits = 0
        self.refreshed = []
        self.last_statement = ""

    def add(self, obj) -> None:
        self.added.append(obj)

    async def commit(self) -> None:
        self.commits += 1

    async def refresh(self, obj) -> None:
        self.refreshed.append(obj)

    async def execute(self, statement):
        self.last_statement = str(statement)
        rows = self.rows

        class Result:
            def scalar_one_or_none(self):
                return rows[0] if rows else None

            def scalars(self):
                return self

            def all(self):
                return rows

        return Result()


def organization(status: str, trial_ends_at=None) -> Organization:
    return Organization(
        id=1,
        name="Acme",
        slug="acme",
        status="active",
        subscription_status=status,
        trial_ends_at=trial_ends_at,
    )


def test_super_admin_can_update_organization_subscription() -> None:
    session = FakeSession()
    org = organization("active")

    updated = asyncio.run(
        update_subscription(
            session,
            org,
            OrganizationSubscriptionUpdate(
                subscription_status="expired",
                subscription_start=datetime(2026, 4, 1, tzinfo=timezone.utc),
                subscription_end=datetime(2026, 4, 25, tzinfo=timezone.utc),
                trial_ends_at=None,
            ),
        )
    )

    assert updated.subscription_status == "expired"
    assert updated.subscription_end is not None
    assert session.commits == 1


def test_admin_cannot_update_subscription() -> None:
    admin = SimpleNamespace(role="admin")

    try:
        asyncio.run(require_super_admin(admin))
    except HTTPException as exc:
        assert exc.status_code == 403
    else:
        raise AssertionError("Expected subscription update to require super admin")


def test_expired_org_cannot_create_scan(monkeypatch) -> None:
    session = FakeSession()
    admin = SimpleNamespace(role="admin", organization_id=1)

    async def fake_user(_session, _user_id):
        return SimpleNamespace(id=1, organization_id=1)

    async def fake_target(_session, _target_id):
        return SimpleNamespace(id=1, organization_id=1)

    async def fake_org(_session, _organization_id):
        return organization("expired")

    monkeypatch.setattr("app.services.scan_service.get_user_by_id", fake_user)
    monkeypatch.setattr("app.services.scan_service.get_target_by_id", fake_target)
    monkeypatch.setattr("app.services.scan_service.require_organization", fake_org)

    try:
        asyncio.run(
            create_scan_for_actor(
                session, ScanCreate(user_id=1, target_id=1, scan_type="full"), admin
            )
        )
    except HTTPException as exc:
        assert exc.detail == EXPIRED_MESSAGE
    else:
        raise AssertionError("Expected expired subscription to block scan")


def test_suspended_org_cannot_create_scan_or_target(monkeypatch) -> None:
    session = FakeSession()
    admin = SimpleNamespace(role="admin", organization_id=1)

    async def fake_user(_session, _user_id):
        return SimpleNamespace(id=1, organization_id=1)

    async def fake_target(_session, _target_id):
        return SimpleNamespace(id=1, organization_id=1)

    async def fake_org(_session, _organization_id):
        return organization("suspended")

    monkeypatch.setattr("app.services.scan_service.get_user_by_id", fake_user)
    monkeypatch.setattr("app.services.scan_service.get_target_by_id", fake_target)
    monkeypatch.setattr("app.services.scan_service.require_organization", fake_org)
    monkeypatch.setattr("app.services.target_service.get_user_by_id", fake_user)
    monkeypatch.setattr("app.services.target_service.require_organization", fake_org)

    for call in (
        create_scan_for_actor(
            session, ScanCreate(user_id=1, target_id=1, scan_type="full"), admin
        ),
        create_target_for_actor(
            session, TargetCreate(user_id=1, base_url="https://example.com"), admin
        ),
    ):
        try:
            asyncio.run(call)
        except HTTPException as exc:
            assert exc.detail == SUSPENDED_MESSAGE
        else:
            raise AssertionError("Expected suspended subscription to block action")


def test_active_org_can_create_scan_if_weekly_limit_allows(monkeypatch) -> None:
    session = FakeSession()
    admin = SimpleNamespace(role="admin", organization_id=1)

    async def fake_user(_session, _user_id):
        return SimpleNamespace(id=1, organization_id=1)

    async def fake_target(_session, _target_id):
        return SimpleNamespace(id=1, organization_id=1)

    async def fake_org(_session, _organization_id):
        return organization("active")

    async def fake_limit(_session, _organization_id):
        return None

    monkeypatch.setattr("app.services.scan_service.get_user_by_id", fake_user)
    monkeypatch.setattr("app.services.scan_service.get_target_by_id", fake_target)
    monkeypatch.setattr("app.services.scan_service.require_organization", fake_org)
    monkeypatch.setattr("app.services.scan_service.enforce_weekly_scan_limit", fake_limit)

    scan = asyncio.run(
        create_scan_for_actor(
            session, ScanCreate(user_id=1, target_id=1, scan_type="full"), admin
        )
    )

    assert scan.organization_id == 1
    assert session.commits == 1


def test_trial_org_can_scan_before_trial_expiry() -> None:
    check_org_subscription(
        organization("trial", datetime.now(timezone.utc) + timedelta(days=1))
    )


def test_trial_org_blocked_after_trial_expiry() -> None:
    try:
        check_org_subscription(
            organization("trial", datetime.now(timezone.utc) - timedelta(seconds=1))
        )
    except HTTPException as exc:
        assert exc.detail == TRIAL_ENDED_MESSAGE
    else:
        raise AssertionError("Expected expired trial to be blocked")


def test_payment_methods_seeded_correctly() -> None:
    session = FakeSession(rows=[])

    asyncio.run(ensure_default_payment_methods(session))

    assert {method.slug for method in session.added} == {
        "stripe",
        "paypal",
        "bank_transfer",
    }


def test_super_admin_can_activate_payment_methods() -> None:
    method = PaymentMethod(id=1, name="Stripe", slug="stripe", is_active=False)
    session = FakeSession(rows=[method])

    updated = asyncio.run(
        update_payment_method(
            session,
            1,
            PaymentMethodUpdate(
                is_active=True,
                description="Pay securely using Stripe checkout.",
                config_json={"display_name": "Credit / Debit Card"},
            ),
        )
    )

    assert updated is not None
    assert updated.is_active is True
    assert updated.config_json == {"display_name": "Credit / Debit Card"}


def test_super_admin_can_save_stripe_secret_encrypted(monkeypatch) -> None:
    monkeypatch.setenv("ENCRYPTION_KEY", "test-encryption-key")
    method = PaymentMethod(id=1, name="Stripe", slug="stripe", is_active=False)
    session = FakeSession(rows=[method])

    updated = asyncio.run(
        update_payment_method(
            session,
            1,
            PaymentMethodUpdate(secret_key="sk_test_secret", mode="test"),
        )
    )

    assert updated is not None
    assert updated.encrypted_secret_key is not None
    assert updated.encrypted_secret_key != "sk_test_secret"
    assert "sk_test_secret" not in updated.encrypted_secret_key


def test_secret_is_not_returned_in_payment_method_response() -> None:
    now = datetime.now(timezone.utc)
    method = PaymentMethod(
        id=1,
        name="Stripe",
        slug="stripe",
        is_active=True,
        mode="test",
        encrypted_secret_key="encrypted-value",
        encrypted_webhook_secret="encrypted-webhook",
        webhook_enabled=True,
        created_at=now,
        updated_at=now,
    )

    payload = _serialize_payment_method(method).model_dump()

    assert "encrypted_secret_key" not in payload
    assert "encrypted_webhook_secret" not in payload
    assert payload["has_secret_key"] is True
    assert payload["has_webhook_secret"] is True


def test_empty_secret_update_keeps_existing_secret(monkeypatch) -> None:
    monkeypatch.setenv("ENCRYPTION_KEY", "test-encryption-key")
    method = PaymentMethod(
        id=1,
        name="Stripe",
        slug="stripe",
        is_active=False,
        encrypted_secret_key="existing-secret",
    )
    session = FakeSession(rows=[method])

    updated = asyncio.run(
        update_payment_method(
            session,
            1,
            PaymentMethodUpdate(secret_key="", webhook_secret=None),
        )
    )

    assert updated is not None
    assert updated.encrypted_secret_key == "existing-secret"


def test_clear_secret_key_removes_existing_secret() -> None:
    method = PaymentMethod(
        id=1,
        name="Stripe",
        slug="stripe",
        is_active=False,
        encrypted_secret_key="existing-secret",
    )
    session = FakeSession(rows=[method])

    updated = asyncio.run(
        update_payment_method(
            session,
            1,
            PaymentMethodUpdate(clear_secret_key=True),
        )
    )

    assert updated is not None
    assert updated.encrypted_secret_key is None


def test_missing_encryption_key_blocks_saving_secret(monkeypatch) -> None:
    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
    method = PaymentMethod(id=1, name="Stripe", slug="stripe", is_active=False)
    session = FakeSession(rows=[method])

    try:
        asyncio.run(
            update_payment_method(
                session,
                1,
                PaymentMethodUpdate(secret_key="sk_test_secret"),
            )
        )
    except RuntimeError as exc:
        assert "ENCRYPTION_KEY" in str(exc)
    else:
        raise AssertionError("Expected missing ENCRYPTION_KEY to block secret save")


def test_admin_cannot_activate_payment_methods() -> None:
    admin = SimpleNamespace(role="admin")

    try:
        asyncio.run(require_super_admin(admin))
    except HTTPException as exc:
        assert exc.status_code == 403
    else:
        raise AssertionError("Expected payment method update to require super admin")


def test_admin_cannot_update_payment_credentials() -> None:
    admin = SimpleNamespace(role="admin")

    try:
        asyncio.run(require_super_admin(admin))
    except HTTPException as exc:
        assert exc.status_code == 403
    else:
        raise AssertionError("Expected credential update to require super admin")


def test_normal_users_only_see_active_payment_methods() -> None:
    active = PaymentMethod(id=1, name="Stripe", slug="stripe", is_active=True)
    inactive = PaymentMethod(id=2, name="PayPal", slug="paypal", is_active=False)
    session = FakeSession(rows=[active, inactive])
    user = SimpleNamespace(role="admin")

    methods = asyncio.run(list_payment_methods(session, user))

    assert "payment_methods.is_active IS true" in session.last_statement
    assert methods == [active, inactive]


def test_active_enabled_webhook_placeholder_accepts_request() -> None:
    method = PaymentMethod(
        id=1,
        name="Stripe",
        slug="stripe",
        is_active=True,
        webhook_enabled=True,
    )
    session = FakeSession(rows=[method])

    class FakeRequest:
        async def json(self):
            return {"type": "checkout.session.completed", "secret": "not-logged"}

    response = asyncio.run(_handle_webhook("stripe", FakeRequest(), session))

    assert response["status"] == "success"


def test_inactive_or_disabled_webhook_placeholder_rejects_request() -> None:
    for method in (
        PaymentMethod(
            id=1,
            name="Stripe",
            slug="stripe",
            is_active=False,
            webhook_enabled=True,
        ),
        PaymentMethod(
            id=1,
            name="Stripe",
            slug="stripe",
            is_active=True,
            webhook_enabled=False,
        ),
    ):
        session = FakeSession(rows=[method])

        class FakeRequest:
            async def json(self):
                return {"type": "event"}

        try:
            asyncio.run(_handle_webhook("stripe", FakeRequest(), session))
        except HTTPException as exc:
            assert exc.status_code == 400
        else:
            raise AssertionError("Expected inactive or disabled webhook to reject")


def test_get_enabled_webhook_method_requires_active_and_enabled() -> None:
    method = PaymentMethod(
        id=1,
        name="PayPal",
        slug="paypal",
        is_active=True,
        webhook_enabled=True,
    )
    session = FakeSession(rows=[method])

    assert asyncio.run(get_enabled_webhook_method(session, "paypal")) == method
