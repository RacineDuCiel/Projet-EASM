from pydantic import BaseModel, ConfigDict
from typing import List, Optional
from uuid import UUID
from datetime import datetime
from src.models.enums import ScanType, ScanStatus
from .asset import AssetCreate # Needed for ScanResult

class ScanBase(BaseModel):
    scan_type: ScanType

class ScanCreate(ScanBase):
    scope_id: UUID

class ScanEventBase(BaseModel):
    message: str
    severity: str = "info"

class ScanEventCreate(ScanEventBase):
    pass

class ScanEvent(ScanEventBase):
    id: UUID
    scan_id: UUID
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class Scan(ScanBase):
    id: UUID
    scope_id: UUID
    status: ScanStatus
    started_at: datetime
    completed_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

class ScanWithEvents(Scan):
    events: List[ScanEvent] = []

class ScanResult(BaseModel):
    status: ScanStatus
    assets: List[AssetCreate]
