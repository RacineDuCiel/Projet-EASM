from pydantic import BaseModel
from typing import Optional
from uuid import UUID
from datetime import datetime

class SystemLogBase(BaseModel):
    level: str = "info"
    message: str
    source: str = "system"
    user_id: Optional[UUID] = None

class SystemLogCreate(SystemLogBase):
    pass

class SystemLog(SystemLogBase):
    id: UUID
    created_at: datetime

    class Config:
        from_attributes = True
