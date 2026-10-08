from pydantic import BaseModel, EmailStr, Field, HttpUrl

class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)

class LoginIn(BaseModel):
    email: EmailStr
    password: str
    otp: str | None = None

class PasswordChangeIn(BaseModel):
    current_password: str
    new_password: str

class URLAnalyzeIn(BaseModel):
    url: str

class PortScanIn(BaseModel):
    target: str = "127.0.0.1"
    start_port: int = Field(default=1, ge=1, le=65535)
    end_port: int = Field(default=1024, ge=1, le=65535)

class IncidentIn(BaseModel):
    title: str
    description: str
    severity: str
    category: str = "Other"
    affected_asset: str = "lab"

class IncidentUpdateIn(BaseModel):
    status: str | None = None
    resolution: str | None = None
    assigned_analyst_id: int | None = None
