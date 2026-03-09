from pydantic import BaseModel, ConfigDict
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

    model_config = ConfigDict(from_attributes=True)
