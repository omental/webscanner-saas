from sqlalchemy import Boolean, ForeignKey, JSON, String, Text
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
    confidence_level: Mapped[str | None] = mapped_column(String(50), nullable=True)
    confidence_score: Mapped[int | None] = mapped_column(nullable=True)
    evidence_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    verification_steps: Mapped[object | None] = mapped_column(JSON, nullable=True)
    payload_used: Mapped[str | None] = mapped_column(Text, nullable=True)
    affected_parameter: Mapped[str | None] = mapped_column(String(255), nullable=True)
    response_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)
    false_positive_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    http_method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    tested_parameter: Mapped[str | None] = mapped_column(String(255), nullable=True)
    payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    baseline_status_code: Mapped[int | None] = mapped_column(nullable=True)
    attack_status_code: Mapped[int | None] = mapped_column(nullable=True)
    baseline_response_size: Mapped[int | None] = mapped_column(nullable=True)
    attack_response_size: Mapped[int | None] = mapped_column(nullable=True)
    baseline_response_time_ms: Mapped[int | None] = mapped_column(nullable=True)
    attack_response_time_ms: Mapped[int | None] = mapped_column(nullable=True)
    response_diff_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    deduplication_key: Mapped[str | None] = mapped_column(String(255), nullable=True)
    comparison_status: Mapped[str | None] = mapped_column(String(50), nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    scan = relationship("Scan", back_populates="findings")
    scan_page = relationship("ScanPage", back_populates="findings")
    references = relationship("FindingReference", back_populates="finding")
