from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class DetectedTechnology(Base):
    __tablename__ = "detected_technologies"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    scan_page_id: Mapped[int | None] = mapped_column(
        ForeignKey("scan_pages.id"), nullable=True
    )
    product_name: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    confidence_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    detection_method: Mapped[str | None] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    scan = relationship("Scan", back_populates="technologies")
    scan_page = relationship("ScanPage", back_populates="technologies")
