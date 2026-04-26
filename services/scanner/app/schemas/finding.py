from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.schemas.finding_reference import FindingReferenceRead


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    scan_page_id: int | None
    category: str
    title: str
    description: str
    severity: str
    confidence: str | None
    evidence: str | None
    remediation: str | None
    is_confirmed: bool
    references: list[FindingReferenceRead]
    created_at: datetime
    updated_at: datetime
