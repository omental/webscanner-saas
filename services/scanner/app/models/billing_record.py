from datetime import datetime
from decimal import Decimal

from sqlalchemy import DateTime, ForeignKey, Numeric, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin


class BillingRecord(TimestampMixin, Base):
    __tablename__ = "billing_records"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id"), nullable=False
    )
    package_id: Mapped[int] = mapped_column(ForeignKey("packages.id"), nullable=False)
    amount: Mapped[Decimal] = mapped_column(Numeric(10, 2), nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False, default="USD")
    billing_period_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    billing_period_end: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="pending")

    organization = relationship("Organization")
    package = relationship("Package")
    invoices = relationship("Invoice", back_populates="billing_record")
