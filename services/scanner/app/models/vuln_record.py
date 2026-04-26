from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin


class VulnRecord(TimestampMixin, Base):
    __tablename__ = "vuln_records"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    primary_id: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    source_priority: Mapped[int] = mapped_column(nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(String, nullable=False, default="")
    severity: Mapped[str | None] = mapped_column(String(50), nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    source_updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    has_cve: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    cve_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    has_kev: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    has_public_exploit: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )

    aliases = relationship("VulnAlias", back_populates="vuln_record")
    affected_products = relationship(
        "VulnAffectedProduct", back_populates="vuln_record"
    )
