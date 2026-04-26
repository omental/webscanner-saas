from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class PaymentMethodRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    slug: str
    is_active: bool
    mode: str
    description: str | None = None
    config_json: dict[str, Any] | None = None
    public_key: str | None = None
    webhook_url: str | None = None
    webhook_enabled: bool
    has_secret_key: bool
    has_webhook_secret: bool
    created_at: datetime
    updated_at: datetime


class PaymentMethodUpdate(BaseModel):
    is_active: bool | None = None
    mode: str | None = Field(default=None, pattern="^(test|live)$")
    description: str | None = None
    config_json: dict[str, Any] | None = None
    public_key: str | None = None
    secret_key: str | None = None
    webhook_secret: str | None = None
    webhook_enabled: bool | None = None
    clear_secret_key: bool = False
    clear_webhook_secret: bool = False
