from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db_session, require_super_admin
from app.models.invoice import Invoice
from app.models.user import User
from app.schemas.invoice import InvoiceRead
from app.services.invoice_service import create_manual_invoice_for_organization
from app.services.organization_service import require_organization

router = APIRouter(prefix="/billing", tags=["billing"])
DbSession = Annotated[AsyncSession, Depends(get_db_session)]
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


@router.post("/generate/{organization_id}", response_model=InvoiceRead)
async def generate_billing_endpoint(
    organization_id: int, session: DbSession, _super_admin: SuperAdmin
) -> InvoiceRead:
    organization = await require_organization(session, organization_id)
    invoice = await create_manual_invoice_for_organization(session, organization)
    return _serialize_invoice(invoice)
