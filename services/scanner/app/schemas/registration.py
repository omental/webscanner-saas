from datetime import datetime

from pydantic import BaseModel, EmailStr, model_validator


class TrialRegistrationCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    organization_name: str
    selected_package_id: int | None = None
    selected_package_slug: str | None = None

    @model_validator(mode="after")
    def require_package_selection(self):
        if self.selected_package_id is None and not self.selected_package_slug:
            raise ValueError("selected_package_id or selected_package_slug is required")
        return self


class TrialRegistrationRead(BaseModel):
    success: bool
    message: str
    trial_ends_at: datetime
    invoice_id: int
    invoice_pdf_url: str
