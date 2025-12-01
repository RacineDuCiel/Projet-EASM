from pydantic import BaseModel, ConfigDict
from typing import Optional
from uuid import UUID
from datetime import datetime
from src.models.enums import UserRole

class UserBase(BaseModel):
    username: str
    role: UserRole = UserRole.user
    program_id: Optional[UUID] = None

class UserCreate(UserBase):
    password: str

class UserUpdate(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    role: Optional[UserRole] = None
    program_id: Optional[UUID] = None
    is_active: Optional[bool] = None

from src.schemas.program import Program

class User(UserBase):
    id: UUID
    is_active: bool
    created_at: datetime
    program: Optional[Program] = None

    model_config = ConfigDict(from_attributes=True)

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenWithUser(Token):
    user: 'User'

class TokenData(BaseModel):
    username: Optional[str] = None
