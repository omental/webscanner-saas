from calendar import monthrange
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

from fastapi import HTTPException, Response
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from reportlab.lib import colors
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.billing_record import BillingRecord
from app.models.invoice import Invoice
from app.models.organization import Organization
from app.models.package import Package
from app.models.user import User

INVOICE_STORAGE_DIR = Path(__file__).resolve().parents[2] / "generated" / "invoices"
INVOICE_NOTE = "This invoice is due after your free trial ends."


def add_one_month(value: datetime) -> datetime:
    month = value.month + 1
    year = value.year
    if month == 13:
        month = 1
        year += 1
    day = min(value.day, monthrange(year, month)[1])
    return value.replace(year=year, month=month, day=day)


def _invoice_path(invoice: Invoice) -> Path:
    return INVOICE_STORAGE_DIR / f"invoice-{invoice.id}.pdf"


async def create_billing_record_for_trial_registration(
    session: AsyncSession,
    organization: Organization,
    package: Package,
    trial_ends_at: datetime,
) -> BillingRecord:
    billing_record = BillingRecord(
        organization_id=organization.id,
        package_id=package.id,
        amount=package.price_monthly,
        currency="USD",
        billing_period_start=trial_ends_at,
        billing_period_end=add_one_month(trial_ends_at),
        status="pending",
    )
    session.add(billing_record)
    await session.flush()
    return billing_record


async def _next_invoice_number(session: AsyncSession, now: datetime) -> str:
    result = await session.execute(select(func.max(Invoice.id)))
    next_id = int(result.scalar_one() or 0) + 1
    return f"INV-{now.year}-{next_id:04d}"


async def create_invoice_for_billing_record(
    session: AsyncSession,
    billing_record: BillingRecord,
    organization: Organization,
    issued_at: datetime,
    due_date: datetime,
) -> Invoice:
    invoice = Invoice(
        organization_id=organization.id,
        billing_record_id=billing_record.id,
        invoice_number=await _next_invoice_number(session, issued_at),
        amount=billing_record.amount,
        currency=billing_record.currency,
        status="unpaid",
        issued_at=issued_at,
        due_date=due_date,
        pdf_url=None,
    )
    session.add(invoice)
    await session.flush()
    invoice.pdf_url = f"/api/v1/invoices/{invoice.id}/download"
    await generate_invoice_pdf(session, invoice.id)
    return invoice


def _format_money(amount: Decimal, currency: str) -> str:
    return f"{currency} {amount:.2f}"


async def _load_invoice(session: AsyncSession, invoice_id: int) -> Invoice | None:
    result = await session.execute(
        select(Invoice)
        .options(
            selectinload(Invoice.organization),
            selectinload(Invoice.billing_record).selectinload(BillingRecord.package),
        )
        .where(Invoice.id == invoice_id)
    )
    return result.scalar_one_or_none()


async def require_invoice(session: AsyncSession, invoice_id: int) -> Invoice:
    invoice = await _load_invoice(session, invoice_id)
    if invoice is None:
        raise HTTPException(status_code=404, detail="Invoice not found")
    return invoice


async def generate_invoice_pdf(session: AsyncSession, invoice_id: int) -> str:
    invoice = await require_invoice(session, invoice_id)
    organization = invoice.organization
    package = invoice.billing_record.package
    INVOICE_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    path = _invoice_path(invoice)

    doc = SimpleDocTemplate(str(path), pagesize=A4, rightMargin=42, leftMargin=42)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("Web Scanner Platform", styles["Title"]),
        Spacer(1, 16),
        Paragraph(f"Invoice {invoice.invoice_number}", styles["Heading1"]),
        Spacer(1, 12),
    ]
    rows = [
        ("Issue date", invoice.issued_at.date().isoformat()),
        ("Due date", invoice.due_date.date().isoformat()),
        ("Organization", organization.name),
        ("Package", package.name),
        ("Amount", _format_money(invoice.amount, invoice.currency)),
        (
            "Billing period",
            f"{invoice.billing_record.billing_period_start.date().isoformat()} to "
            f"{invoice.billing_record.billing_period_end.date().isoformat()}",
        ),
        ("Status", invoice.status.title()),
    ]
    table = Table(rows, colWidths=[140, 330])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef2ff")),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#0f172a")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.extend([table, Spacer(1, 20), Paragraph(INVOICE_NOTE, styles["BodyText"])])
    doc.build(story)
    invoice.pdf_url = f"/api/v1/invoices/{invoice.id}/download"
    await session.flush()
    return invoice.pdf_url


async def get_invoice_download_response(
    session: AsyncSession, invoice_id: int
) -> Response:
    invoice = await require_invoice(session, invoice_id)
    path = _invoice_path(invoice)
    if not path.exists():
        await generate_invoice_pdf(session, invoice_id)
    return Response(
        content=path.read_bytes(),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{invoice.invoice_number}.pdf"'
        },
    )


async def list_invoices_for_actor(session: AsyncSession, actor: User) -> list[Invoice]:
    query = (
        select(Invoice)
        .options(
            selectinload(Invoice.organization),
            selectinload(Invoice.billing_record).selectinload(BillingRecord.package),
        )
        .order_by(Invoice.id.desc())
    )
    if actor.role == "admin":
        query = query.where(Invoice.organization_id == actor.organization_id)
    elif actor.role != "super_admin":
        raise HTTPException(status_code=403, detail="Invoice access denied")
    result = await session.execute(query)
    return list(result.scalars().all())


async def require_invoice_for_actor(
    session: AsyncSession, invoice_id: int, actor: User
) -> Invoice:
    if actor.role not in {"admin", "super_admin"}:
        raise HTTPException(status_code=403, detail="Invoice access denied")
    invoice = await require_invoice(session, invoice_id)
    if actor.role == "admin" and invoice.organization_id != actor.organization_id:
        raise HTTPException(status_code=404, detail="Invoice not found")
    return invoice


async def mark_invoice_paid(session: AsyncSession, invoice_id: int) -> Invoice:
    invoice = await require_invoice(session, invoice_id)
    invoice.status = "paid"
    invoice.paid_at = datetime.now(timezone.utc)
    if invoice.billing_record is not None:
        invoice.billing_record.status = "paid"
    await generate_invoice_pdf(session, invoice.id)
    await session.commit()
    await session.refresh(invoice)
    return await require_invoice(session, invoice.id)


async def create_manual_invoice_for_organization(
    session: AsyncSession, organization: Organization, now: datetime | None = None
) -> Invoice:
    if organization.package is None:
        raise HTTPException(status_code=400, detail="Organization package is required")
    current = now or datetime.now(timezone.utc)
    billing_record = BillingRecord(
        organization_id=organization.id,
        package_id=organization.package.id,
        amount=organization.package.price_monthly,
        currency="USD",
        billing_period_start=current,
        billing_period_end=add_one_month(current),
        status="pending",
    )
    session.add(billing_record)
    await session.flush()
    invoice = await create_invoice_for_billing_record(
        session,
        billing_record,
        organization,
        issued_at=current,
        due_date=current,
    )
    await session.commit()
    await session.refresh(invoice)
    return await require_invoice(session, invoice.id)
