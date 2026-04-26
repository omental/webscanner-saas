from datetime import datetime

from pydantic import BaseModel


class UsageRead(BaseModel):
    organization_id: int
    organization_name: str
    package_name: str | None
    subscription_status: str
    trial_ends_at: datetime | None = None
    subscription_end: datetime | None = None
    scan_limit_per_week: int
    scans_used_this_week: int
    scans_remaining_this_week: int
    trial_scan_limit: int = 1
    trial_scans_used: int = 0
    trial_scans_remaining: int = 1
    is_trial_limit_reached: bool = False
    is_blocked: bool = False
    current_invoice_id: int | None = None
    current_invoice_status: str | None = None
    current_invoice_pdf_url: str | None = None
    week_start: datetime
    week_end: datetime
    status: str
