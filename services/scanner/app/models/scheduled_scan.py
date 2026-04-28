from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin


class ScheduledScan(TimestampMixin, Base):
    __tablename__ = "scheduled_scans"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id"), nullable=False
    )
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), nullable=False)
    created_by_user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"), nullable=False
    )
    scan_profile: Mapped[str | None] = mapped_column(
        String(50), nullable=True, default="standard"
    )
    frequency: Mapped[str] = mapped_column(String(50), nullable=False)
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    organization = relationship("Organization", back_populates="scheduled_scans")
    target = relationship("Target", back_populates="scheduled_scans")
    created_by_user = relationship("User", back_populates="scheduled_scans")
