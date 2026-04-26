from datetime import datetime

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class GhsaRecord(Base):
    __tablename__ = "ghsa_records"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    ghsa_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    cve_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str | None] = mapped_column(String(50), nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    permalink: Mapped[str | None] = mapped_column(String(1024), nullable=True)
