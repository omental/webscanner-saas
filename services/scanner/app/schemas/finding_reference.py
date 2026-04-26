from datetime import datetime

from pydantic import BaseModel, ConfigDict


class FindingReferenceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    finding_id: int
    ref_type: str
    ref_value: str
    ref_url: str | None
    source: str | None
    created_at: datetime
