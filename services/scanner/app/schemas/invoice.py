from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict


class BillingRecordRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    organization_id: int
    package_id: int
    amount: Decimal
    currency: str
    billing_period_start: datetime
    billing_period_end: datetime
    status: str
    created_at: datetime
    updated_at: datetime


class InvoiceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    organization_id: int
    organization_name: str | None = None
    billing_record_id: int
    package_id: int | None = None
    package_name: str | None = None
    invoice_number: str
    amount: Decimal
    currency: str
    status: str
    issued_at: datetime
    due_date: datetime
    paid_at: datetime | None = None
    pdf_url: str | None = None
    created_at: datetime
    updated_at: datetime
