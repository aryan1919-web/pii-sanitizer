from pydantic import BaseModel, EmailStr
from datetime import datetime
from app.models import Role


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: Role = Role.USER


class UserOut(BaseModel):
    id: str
    username: str
    email: str
    role: Role
    created_at: datetime
    model_config = {"from_attributes": True}


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    sub: str
    role: str


class LoginRequest(BaseModel):
    username: str
    password: str


class AuditLogOut(BaseModel):
    id: str
    user_id: str
    action: str
    target_file: str | None
    details: str | None
    timestamp: datetime
    model_config = {"from_attributes": True}


class FileOut(BaseModel):
    id: str
    original_filename: str
    mode: str
    pii_count: int
    created_at: datetime
    model_config = {"from_attributes": True}
