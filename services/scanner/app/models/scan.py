from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin


class Scan(TimestampMixin, Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("organizations.id"), nullable=True
    )
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), nullable=False)
    scan_type: Mapped[str] = mapped_column(String(50), nullable=False)
    scan_profile: Mapped[str | None] = mapped_column(
        String(50), nullable=True, default="standard"
    )
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="queued")
    total_pages_found: Mapped[int] = mapped_column(nullable=False, default=0)
    total_findings: Mapped[int] = mapped_column(nullable=False, default=0)
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_depth: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_pages: Mapped[int | None] = mapped_column(Integer, nullable=True)
    timeout_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    previous_scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id"), nullable=True
    )
    error_message: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    user = relationship("User", back_populates="scans")
    organization = relationship("Organization", back_populates="scans")
    target = relationship("Target", back_populates="scans")
    previous_scan = relationship("Scan", remote_side=[id])
    pages = relationship("ScanPage", back_populates="scan")
    findings = relationship("Finding", back_populates="scan")
    technologies = relationship("DetectedTechnology", back_populates="scan")
