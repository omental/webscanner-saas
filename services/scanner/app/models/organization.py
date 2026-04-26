from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin


class Organization(TimestampMixin, Base):
    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    package_id: Mapped[int | None] = mapped_column(
        ForeignKey("packages.id"), nullable=True
    )
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="active")
    subscription_status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="active"
    )
    subscription_start: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    subscription_end: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    trial_ends_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    package = relationship("Package", back_populates="organizations")
    users = relationship("User", back_populates="organization")
    targets = relationship("Target", back_populates="organization")
    scans = relationship("Scan", back_populates="organization")
