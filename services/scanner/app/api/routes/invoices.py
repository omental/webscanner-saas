from typing import Annotated

from fastapi import APIRouter, Depends, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    get_db_session,
    require_authenticated_user,
    require_super_admin,
)
from app.models.invoice import Invoice
from app.models.user import User
from app.schemas.invoice import InvoiceRead
from app.services.invoice_service import (
    get_invoice_download_response,
    list_invoices_for_actor,
    mark_invoice_paid,
    require_invoice_for_actor,
)

router = APIRouter(prefix="/invoices", tags=["invoices"])
DbSession = Annotated[AsyncSession, Depends(get_db_session)]
CurrentUser = Annotated[User, Depends(require_authenticated_user)]
SuperAdmin = Annotated[User, Depends(require_super_admin)]


def _serialize_invoice(invoice: Invoice) -> InvoiceRead:
    billing_record = invoice.billing_record
    package = billing_record.package if billing_record else None
    return InvoiceRead.model_validate(
        {
            "id": invoice.id,
            "organization_id": invoice.organization_id,
            "organization_name": invoice.organization.name
            if invoice.organization
            else None,
            "billing_record_id": invoice.billing_record_id,
            "package_id": billing_record.package_id if billing_record else None,
            "package_name": package.name if package else None,
            "invoice_number": invoice.invoice_number,
            "amount": invoice.amount,
            "currency": invoice.currency,
            "status": invoice.status,
            "issued_at": invoice.issued_at,
            "due_date": invoice.due_date,
            "paid_at": invoice.paid_at,
            "pdf_url": invoice.pdf_url,
            "created_at": invoice.created_at,
            "updated_at": invoice.updated_at,
        }
    )


@router.get("", response_model=list[InvoiceRead])
async def list_invoices_endpoint(
    session: DbSession, current_user: CurrentUser
) -> list[InvoiceRead]:
    invoices = await list_invoices_for_actor(session, current_user)
    return [_serialize_invoice(invoice) for invoice in invoices]


@router.get("/{invoice_id}", response_model=InvoiceRead)
async def get_invoice_endpoint(
    invoice_id: int, session: DbSession, current_user: CurrentUser
) -> InvoiceRead:
    invoice = await require_invoice_for_actor(session, invoice_id, current_user)
    return _serialize_invoice(invoice)


@router.get("/{invoice_id}/download")
async def download_invoice_endpoint(
    invoice_id: int, session: DbSession, current_user: CurrentUser
) -> Response:
    await require_invoice_for_actor(session, invoice_id, current_user)
    return await get_invoice_download_response(session, invoice_id)


@router.patch("/{invoice_id}/mark-paid", response_model=InvoiceRead)
async def mark_invoice_paid_endpoint(
    invoice_id: int, session: DbSession, _super_admin: SuperAdmin
) -> InvoiceRead:
    invoice = await mark_invoice_paid(session, invoice_id)
    return _serialize_invoice(invoice)
