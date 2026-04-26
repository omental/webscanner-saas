from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class FindingReference(Base):
    __tablename__ = "finding_references"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), nullable=False)
    ref_type: Mapped[str] = mapped_column(String(50), nullable=False)
    ref_value: Mapped[str] = mapped_column(String(255), nullable=False)
    ref_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    source: Mapped[str | None] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    finding = relationship("Finding", back_populates="references")
