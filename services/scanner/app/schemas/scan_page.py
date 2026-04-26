from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ScanPageRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    url: str
    method: str
    status_code: int | None
    content_type: str | None
    response_time_ms: int | None
    page_title: str | None
    discovered_from: str | None
    depth: int
    created_at: datetime
