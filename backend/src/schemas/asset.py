from pydantic import BaseModel, ConfigDict
from typing import List, Optional
from uuid import UUID
from datetime import datetime
from src.models.enums import AssetType, Severity, VulnStatus

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
    status: VulnStatus = VulnStatus.open

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
