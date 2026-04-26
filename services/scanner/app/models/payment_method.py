from sqlalchemy import Boolean, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin


class PaymentMethod(TimestampMixin, Base):
    __tablename__ = "payment_methods"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    mode: Mapped[str] = mapped_column(String(20), nullable=False, default="test")
    description: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    config_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    public_key: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    encrypted_secret_key: Mapped[str | None] = mapped_column(String(4000), nullable=True)
    webhook_url: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    encrypted_webhook_secret: Mapped[str | None] = mapped_column(
        String(4000), nullable=True
    )
    webhook_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )

    @property
    def has_secret_key(self) -> bool:
        return bool(self.encrypted_secret_key)

    @property
    def has_webhook_secret(self) -> bool:
        return bool(self.encrypted_webhook_secret)
