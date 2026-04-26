from sqlalchemy import Boolean, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin


class Finding(TimestampMixin, Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    scan_page_id: Mapped[int | None] = mapped_column(
        ForeignKey("scan_pages.id"), nullable=True
    )
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(50), nullable=False)
    confidence: Mapped[str | None] = mapped_column(String(50), nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    scan = relationship("Scan", back_populates="findings")
    scan_page = relationship("ScanPage", back_populates="findings")
    references = relationship("FindingReference", back_populates="finding")
