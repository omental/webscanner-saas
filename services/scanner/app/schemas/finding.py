from datetime import datetime
from typing import Any

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
    confidence_level: str | None
    confidence_score: int | None
    evidence_type: str | None
    verification_steps: Any | None
    payload_used: str | None
    affected_parameter: str | None
    response_snippet: str | None
    false_positive_notes: str | None
    request_url: str | None
    http_method: str | None
    tested_parameter: str | None
    payload: str | None
    baseline_status_code: int | None
    attack_status_code: int | None
    baseline_response_size: int | None
    attack_response_size: int | None
    baseline_response_time_ms: int | None
    attack_response_time_ms: int | None
    response_diff_summary: str | None
    deduplication_key: str | None
    comparison_status: str | None
    evidence: str | None
    remediation: str | None
    is_confirmed: bool
    references: list[FindingReferenceRead]
    created_at: datetime
    updated_at: datetime
