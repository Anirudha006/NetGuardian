from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class Token(BaseModel):
    access_token: str
    token_type: str
    role: str
    username: str
    csrf_token: Optional[str] = None

class TokenPayload(BaseModel):
    sub: Optional[str] = None
    role: Optional[str] = None
    exp: Optional[int] = None

class LoginRequest(BaseModel):
    username: str
    password: str

class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: str = "ANALYST"

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str
    created_at: datetime
    last_login: Optional[datetime] = None

    model_config = {"from_attributes": True}
