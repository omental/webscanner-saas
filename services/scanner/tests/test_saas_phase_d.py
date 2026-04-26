import asyncio
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from types import SimpleNamespace

from fastapi import HTTPException

from app.models.organization import Organization
from app.models.package import Package
from app.models.user import User
from app.schemas.registration import TrialRegistrationCreate
from app.services.invoice_service import (
    add_one_month,
    get_invoice_download_response,
    mark_invoice_paid,
    require_invoice_for_actor,
)
from app.services.registration_service import register_trial_admin
from app.services.usage_service import enforce_trial_scan_limit


class Result:
    def __init__(self, one=None, rows=None, scalar=0) -> None:
        self.one = one
        self.rows = rows or []
        self.scalar = scalar

    def scalar_one_or_none(self):
        return self.one

    def scalar_one(self):
        return self.scalar

    def scalars(self):
        return self

    def all(self):
        return self.rows


class FakeSession:
    def __init__(self) -> None:
        self.added = []
        self.commits = 0
        self.flushes = 0
        self.refreshed = []
        self.trial_scan_count = 0
        self.package = Package(
            id=7,
            name="Silver",
            slug="silver",
            scan_limit_per_week=10,
            price_monthly=Decimal("19.00"),
            status="active",
        )

    def add(self, obj) -> None:
        if getattr(obj, "id", None) is None:
            obj.id = len(self.added) + 1
        self.added.append(obj)

    async def flush(self) -> None:
        self.flushes += 1

    async def commit(self) -> None:
        self.commits += 1

    async def refresh(self, obj) -> None:
        self.refreshed.append(obj)

    async def execute(self, statement):
        text = str(statement)
        if "FROM users" in text:
            return Result(one=None)
        if "FROM packages" in text:
            return Result(one=self.package)
        if "FROM organizations" in text:
            return Result(one=None)
        if "count(scans.id)" in text:
            return Result(scalar=self.trial_scan_count)
        return Result(one=None, scalar=0)


def test_trial_registration_creates_org_admin_billing_and_invoice(monkeypatch) -> None:
    session = FakeSession()
    created = {}

    async def fake_billing_record(_session, organization, package, trial_ends_at):
        created["billing"] = SimpleNamespace(
            id=11,
            organization_id=organization.id,
            package_id=package.id,
            amount=package.price_monthly,
            currency="USD",
            billing_period_start=trial_ends_at,
            billing_period_end=add_one_month(trial_ends_at),
            status="pending",
        )
        return created["billing"]

    async def fake_invoice(_session, billing_record, organization, issued_at, due_date):
        created["invoice"] = SimpleNamespace(
            id=22,
            organization_id=organization.id,
            billing_record_id=billing_record.id,
            amount=billing_record.amount,
            currency=billing_record.currency,
            status="unpaid",
            issued_at=issued_at,
            due_date=due_date,
            pdf_url="/api/v1/invoices/22/download",
        )
        return created["invoice"]

    async def noop_packages(_session):
        return None

    monkeypatch.setattr(
        "app.services.registration_service.ensure_default_packages", noop_packages
    )
    monkeypatch.setattr(
        "app.services.registration_service.create_billing_record_for_trial_registration",
        fake_billing_record,
    )
    monkeypatch.setattr(
        "app.services.registration_service.create_invoice_for_billing_record",
        fake_invoice,
    )

    before = datetime.now(timezone.utc)
    response = asyncio.run(
        register_trial_admin(
            session,
            TrialRegistrationCreate(
                name="Admin",
                email="admin@example.com",
                password="password",
                organization_name="Acme",
                selected_package_id=7,
            ),
        )
    )
    after = datetime.now(timezone.utc)

    organization = next(item for item in session.added if isinstance(item, Organization))
    user = next(item for item in session.added if isinstance(item, User))
    assert organization.subscription_status == "trial"
    assert (
        before + timedelta(days=14)
        <= organization.trial_ends_at
        <= after + timedelta(days=14)
    )
    assert organization.package_id == 7
    assert user.role == "admin"
    assert user.organization_id == organization.id
    assert created["billing"].organization_id == organization.id
    assert created["invoice"].due_date == organization.trial_ends_at
    assert response.invoice_pdf_url == "/api/v1/invoices/22/download"


def test_trial_scan_limit_allows_first_scan_and_blocks_second() -> None:
    session = FakeSession()
    organization = Organization(
        id=1,
        name="Acme",
        slug="acme",
        subscription_status="trial",
        subscription_start=datetime.now(timezone.utc),
        trial_ends_at=datetime.now(timezone.utc) + timedelta(days=14),
    )

    asyncio.run(enforce_trial_scan_limit(session, organization))

    session.trial_scan_count = 1
    try:
        asyncio.run(enforce_trial_scan_limit(session, organization))
    except HTTPException as exc:
        assert exc.detail == "Your free trial includes 1 scan. Upgrade to continue scanning."
    else:
        raise AssertionError("Expected second trial scan to be blocked")


def test_admin_invoice_access_is_scoped_to_own_organization(monkeypatch) -> None:
    own_invoice = SimpleNamespace(id=1, organization_id=10)
    other_invoice = SimpleNamespace(id=2, organization_id=20)
    admin = SimpleNamespace(role="admin", organization_id=10)

    async def fake_require_invoice(_session, invoice_id):
        return own_invoice if invoice_id == 1 else other_invoice

    monkeypatch.setattr("app.services.invoice_service.require_invoice", fake_require_invoice)

    assert asyncio.run(require_invoice_for_actor(SimpleNamespace(), 1, admin)) == own_invoice
    try:
        asyncio.run(require_invoice_for_actor(SimpleNamespace(), 2, admin))
    except HTTPException as exc:
        assert exc.status_code == 404
    else:
        raise AssertionError("Expected admin to be blocked from another org invoice")


def test_super_admin_can_mark_invoice_paid(monkeypatch) -> None:
    invoice = SimpleNamespace(
        id=1,
        status="unpaid",
        paid_at=None,
        billing_record=SimpleNamespace(status="pending"),
    )
    session = FakeSession()

    async def fake_require_invoice(_session, _invoice_id):
        return invoice

    async def fake_generate_pdf(_session, _invoice_id):
        return "/api/v1/invoices/1/download"

    monkeypatch.setattr("app.services.invoice_service.require_invoice", fake_require_invoice)
    monkeypatch.setattr("app.services.invoice_service.generate_invoice_pdf", fake_generate_pdf)

    updated = asyncio.run(mark_invoice_paid(session, 1))

    assert updated.status == "paid"
    assert updated.billing_record.status == "paid"
    assert updated.paid_at is not None


def test_invoice_pdf_download_response_works(monkeypatch, tmp_path) -> None:
    invoice = SimpleNamespace(id=1, invoice_number="INV-2026-0001")
    path = tmp_path / "invoice.pdf"
    path.write_bytes(b"%PDF-1.4 invoice")

    async def fake_require_invoice(_session, _invoice_id):
        return invoice

    monkeypatch.setattr("app.services.invoice_service.require_invoice", fake_require_invoice)
    monkeypatch.setattr("app.services.invoice_service._invoice_path", lambda _invoice: path)

    response = asyncio.run(get_invoice_download_response(SimpleNamespace(), 1))

    assert response.media_type == "application/pdf"
    assert response.body.startswith(b"%PDF")
    assert "INV-2026-0001.pdf" in response.headers["content-disposition"]


def test_manual_billing_period_adds_one_month() -> None:
    start = datetime(2026, 1, 31, tzinfo=timezone.utc)

    assert add_one_month(start) == datetime(2026, 2, 28, tzinfo=timezone.utc)
