from datetime import datetime

from pydantic import BaseModel, ConfigDict


class DetectedTechnologyRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    scan_page_id: int | None
    product_name: str
    category: str
    version: str | None
    vendor: str | None
    confidence_score: float | None
    detection_method: str | None
    created_at: datetime
