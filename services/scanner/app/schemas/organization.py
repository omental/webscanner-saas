from datetime import datetime

from pydantic import BaseModel, ConfigDict

SubscriptionStatus = str


class OrganizationCreate(BaseModel):
    name: str
    slug: str
    package_id: int | None = None
    status: str = "active"


class OrganizationUpdate(BaseModel):
    name: str | None = None
    slug: str | None = None
    status: str | None = None


class OrganizationPackageUpdate(BaseModel):
    package_id: int | None


class OrganizationSubscriptionUpdate(BaseModel):
    subscription_status: SubscriptionStatus
    subscription_start: datetime | None = None
    subscription_end: datetime | None = None
    trial_ends_at: datetime | None = None


class OrganizationTrialStart(BaseModel):
    days: int = 14


class OrganizationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    slug: str
    package_id: int | None
    package_name: str | None = None
    status: str
    subscription_status: str
    subscription_start: datetime | None = None
    subscription_end: datetime | None = None
    trial_ends_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
