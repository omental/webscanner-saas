from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.detected_technology import DetectedTechnologyRead
from app.schemas.finding import FindingRead
from app.schemas.scan_page import ScanPageRead
from app.schemas.target import TargetRead


class ScanCreate(BaseModel):
    user_id: int
    target_id: int
    scan_type: str
    scan_profile: Literal["passive", "quick", "standard", "deep", "aggressive"] = (
        "standard"
    )
    status: str = "queued"
    max_depth: int | None = Field(default=None, ge=0, le=10)
    max_pages: int | None = Field(default=None, ge=1, le=1000)
    timeout_seconds: int | None = Field(default=None, ge=3, le=60)
    previous_scan_id: int | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int
    organization_id: int | None = None
    target_id: int
    scan_type: str
    scan_profile: str | None = "standard"
    status: str
    total_pages_found: int
    total_findings: int
    risk_score: int | None = None
    max_depth: int | None = None
    max_pages: int | None = None
    timeout_seconds: int | None = None
    previous_scan_id: int | None = None
    comparison_summary: dict[str, int] | None = None
    error_message: str | None = None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime
    updated_at: datetime


class ScanDetailRead(ScanRead):
    target: TargetRead | None = None
    completed_at: datetime | None = None
    findings: list[FindingRead] = Field(default_factory=list)
    technologies: list[DetectedTechnologyRead] = Field(default_factory=list)
    pages: list[ScanPageRead] = Field(default_factory=list)


class ScanComparisonRead(BaseModel):
    previous_scan_id: int | None = None
    current_scan_id: int
    fixed_findings: list[FindingRead] = Field(default_factory=list)
    still_vulnerable_findings: list[FindingRead] = Field(default_factory=list)
    new_findings: list[FindingRead] = Field(default_factory=list)
    existing_findings: list[FindingRead] = Field(default_factory=list)
    not_retested_findings: list[FindingRead] = Field(default_factory=list)
    summary: dict[str, int] = Field(default_factory=dict)
