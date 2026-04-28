from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict


ScanFrequency = Literal["weekly", "monthly", "custom"]
ScanProfile = Literal["passive", "quick", "standard", "deep", "aggressive"]


class ScheduledScanCreate(BaseModel):
    target_id: int
    scan_profile: ScanProfile = "standard"
    frequency: ScanFrequency
    next_run_at: datetime
    is_active: bool = True


class ScheduledScanUpdate(BaseModel):
    scan_profile: ScanProfile | None = None
    frequency: ScanFrequency | None = None
    next_run_at: datetime | None = None
    is_active: bool | None = None


class ScheduledScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    organization_id: int
    target_id: int
    created_by_user_id: int
    scan_profile: str | None = "standard"
    frequency: str
    next_run_at: datetime
    last_run_at: datetime | None = None
    is_active: bool
    created_at: datetime
    updated_at: datetime
