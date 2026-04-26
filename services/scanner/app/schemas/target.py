from datetime import datetime

from pydantic import BaseModel, ConfigDict


class TargetCreate(BaseModel):
    user_id: int
    base_url: str


class TargetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int
    organization_id: int | None = None
    base_url: str
    normalized_domain: str
    created_at: datetime
    updated_at: datetime
