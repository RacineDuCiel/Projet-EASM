from pydantic import BaseModel, ConfigDict
from typing import List, Optional
from uuid import UUID
from datetime import datetime
from .models import ScopeType, ScanType, ScanStatus, AssetType, Severity, VulnStatus

class ScopeBase(BaseModel):
    scope_type: ScopeType
    value: str

class ScopeCreate(ScopeBase):
    pass

class Scope(ScopeBase):
    id: UUID
    program_id: UUID
    
    model_config = ConfigDict(from_attributes=True)

class ProgramBase(BaseModel):
    name: str

class ProgramCreate(ProgramBase):
    pass

class Program(ProgramBase):
    id: UUID
    created_at: datetime
    scopes: List[Scope] = []

    model_config = ConfigDict(from_attributes=True)

class ScanBase(BaseModel):
    scan_type: ScanType

class ScanCreate(ScanBase):
    scope_id: UUID

class Scan(ScanBase):
    id: UUID
    scope_id: UUID
    status: ScanStatus
    started_at: datetime
    completed_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

class ServiceBase(BaseModel):
    port: int
    protocol: str
    service_name: Optional[str] = None
    banner: Optional[str] = None

class ServiceCreate(ServiceBase):
    pass

class Service(ServiceBase):
    id: UUID
    asset_id: UUID

    model_config = ConfigDict(from_attributes=True)

class VulnerabilityBase(BaseModel):
    title: str
    severity: Severity
    description: Optional[str] = None
    status: VulnStatus

class VulnerabilityCreate(VulnerabilityBase):
    pass

class Vulnerability(VulnerabilityBase):
    id: UUID
    asset_id: UUID
    service_id: Optional[UUID] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class AssetBase(BaseModel):
    value: str
    asset_type: AssetType
    is_active: bool

class AssetCreate(AssetBase):
    services: List[ServiceCreate] = []
    vulnerabilities: List[VulnerabilityCreate] = []

class Asset(AssetBase):
    id: UUID
    scope_id: UUID
    first_seen: datetime
    last_seen: datetime
    services: List[Service] = []
    vulnerabilities: List[Vulnerability] = []

    model_config = ConfigDict(from_attributes=True)

class ScanResult(BaseModel):
    status: ScanStatus
    assets: List[AssetCreate]
