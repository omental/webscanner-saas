from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field


class PackageRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    slug: str
    scan_limit_per_week: int
    price_monthly: Decimal
    status: str
    created_at: datetime
    updated_at: datetime


class PackageUpdate(BaseModel):
    name: str | None = None
    slug: str | None = None
    scan_limit_per_week: int | None = Field(default=None, ge=0)
    price_monthly: Decimal | None = Field(default=None, ge=0)
    status: str | None = None
