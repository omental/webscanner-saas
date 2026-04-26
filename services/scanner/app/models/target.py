from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin


class Target(TimestampMixin, Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("organizations.id"), nullable=True
    )
    base_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    normalized_domain: Mapped[str] = mapped_column(String(255), nullable=False)

    user = relationship("User", back_populates="targets")
    organization = relationship("Organization", back_populates="targets")
    scans = relationship("Scan", back_populates="target")
