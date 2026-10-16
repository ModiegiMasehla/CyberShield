from typing import Literal

from pydantic import BaseModel, EmailStr, Field

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
IncidentStatusLit = Literal["OPEN", "INVESTIGATING", "CONTAINED", "ERADICATED", "RECOVERED", "CLOSED"]
AlertStatusLit = Literal["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]


class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class LoginIn(BaseModel):
    email: str = Field(max_length=255)
    password: str = Field(max_length=128)
    otp: str | None = Field(default=None, max_length=10)


class PasswordChangeIn(BaseModel):
    current_password: str = Field(max_length=128)
    new_password: str = Field(max_length=128)


class PasswordAnalyzeIn(BaseModel):
    password: str = Field(default="", max_length=256)


class MFACodeIn(BaseModel):
    code: str = Field(min_length=6, max_length=10)


class URLAnalyzeIn(BaseModel):
    url: str = Field(max_length=2048)


class PortScanIn(BaseModel):
    target: str = "127.0.0.1"
    start_port: int = Field(default=1, ge=1, le=65535)
    end_port: int = Field(default=1024, ge=1, le=65535)


class IncidentIn(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    description: str = Field(min_length=1, max_length=5000)
    severity: Severity
    category: str = Field(default="Other", max_length=64)
    affected_asset: str = Field(default="lab", max_length=255)


class IncidentUpdateIn(BaseModel):
    status: IncidentStatusLit | None = None
    resolution: str | None = Field(default=None, max_length=5000)
    assigned_analyst_id: int | None = None


class AlertUpdateIn(BaseModel):
    status: AlertStatusLit | None = None
    assigned_analyst_id: int | None = None
