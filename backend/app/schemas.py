from typing import Literal

from pydantic import BaseModel, EmailStr, Field, model_validator

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


class _PartialUpdate(BaseModel):
    """PATCH body: omitted fields are untouched; only `assigned_analyst_id` may be set to null (unassign)."""

    @model_validator(mode="after")
    def reject_null_for_required_fields(self):
        for name in self.model_fields_set - {"assigned_analyst_id"}:
            if getattr(self, name) is None:
                raise ValueError(f"{name} cannot be null")
        return self


class IncidentUpdateIn(_PartialUpdate):
    status: IncidentStatusLit | None = None
    resolution: str | None = Field(default=None, max_length=5000)
    assigned_analyst_id: int | None = None


class AlertUpdateIn(_PartialUpdate):
    status: AlertStatusLit | None = None
    assigned_analyst_id: int | None = None
