from datetime import datetime

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class KevEntry(Base):
    __tablename__ = "kev_entries"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    cve_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    vendor_project: Mapped[str | None] = mapped_column(String(255), nullable=True)
    product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    vulnerability_name: Mapped[str | None] = mapped_column(String(500), nullable=True)
    date_added: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    due_date: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    required_action: Mapped[str | None] = mapped_column(Text, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
