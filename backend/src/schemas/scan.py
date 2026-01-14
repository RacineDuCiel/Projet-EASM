from pydantic import BaseModel, ConfigDict
from typing import List, Optional
from uuid import UUID
from datetime import datetime
from src.models.enums import ScanType, ScanStatus, ScanDepth
from .asset import AssetCreate # Needed for ScanResult

class ScanBase(BaseModel):
    scan_type: ScanType
    scan_depth: ScanDepth = ScanDepth.fast

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
    scan_depth: ScanDepth
    status: ScanStatus
    started_at: datetime
    completed_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

class ScanWithEvents(Scan):
    events: List[ScanEvent] = []

class ScanResult(BaseModel):
    status: ScanStatus
    assets: List[AssetCreate]


class ScanConfig(BaseModel):
    """Configuration passed to workers for scan execution."""
    scan_id: str
    target: str
    scan_depth: ScanDepth
    # Port configuration
    ports: str  # Resolved ports based on depth and custom settings
    # Nuclei configuration
    nuclei_rate_limit: int
    nuclei_timeout: int
    nuclei_retries: int
    # Derived from depth
    enable_full_vuln_scan: bool  # True only for deep mode
