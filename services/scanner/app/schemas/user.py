from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr

UserRole = Literal["super_admin", "admin", "team_member"]
UserStatus = Literal["active", "inactive"]


class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: UserRole = "team_member"
    organization_id: int | None = None
    status: UserStatus = "active"


class UserUpdate(BaseModel):
    name: str | None = None
    email: EmailStr | None = None
    password: str | None = None
    role: UserRole | None = None
    organization_id: int | None = None
    status: UserStatus | None = None


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    email: EmailStr
    role: UserRole
    organization_id: int | None = None
    organization_name: str | None = None
    status: UserStatus
    created_at: datetime
    updated_at: datetime
