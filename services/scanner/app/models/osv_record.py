from datetime import datetime

from sqlalchemy import JSON, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class OsvRecord(Base):
    __tablename__ = "osv_records"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    osv_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    modified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    ecosystem_specific: Mapped[dict | None] = mapped_column(JSON, nullable=True)
