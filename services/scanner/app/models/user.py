from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin


class User(TimestampMixin, Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("organizations.id"), nullable=True
    )
    role: Mapped[str] = mapped_column(String(50), nullable=False, default="team_member")
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="active"
    )

    organization = relationship("Organization", back_populates="users")
    targets = relationship("Target", back_populates="user")
    scans = relationship("Scan", back_populates="user")
    scheduled_scans = relationship("ScheduledScan", back_populates="created_by_user")
