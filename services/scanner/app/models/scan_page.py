from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class ScanPage(Base):
    __tablename__ = "scan_pages"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    method: Mapped[str] = mapped_column(String(16), nullable=False, default="GET")
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    response_time_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    page_title: Mapped[str | None] = mapped_column(String(512), nullable=True)
    response_headers: Mapped[dict[str, str] | None] = mapped_column(JSON, nullable=True)
    response_body_excerpt: Mapped[str | None] = mapped_column(Text, nullable=True)
    discovered_from: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    depth: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    scan = relationship("Scan", back_populates="pages")
    findings = relationship("Finding", back_populates="scan_page")
    technologies = relationship("DetectedTechnology", back_populates="scan_page")
