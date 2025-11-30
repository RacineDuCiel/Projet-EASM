from pydantic import BaseModel, ConfigDict, field_validator
from typing import List, Optional
from uuid import UUID
from datetime import datetime
from .models import ScopeType, ScanType, ScanStatus, AssetType, Severity, VulnStatus
from . import validators

class ScopeBase(BaseModel):
    scope_type: ScopeType
    value: str

class ScopeCreate(ScopeBase):
    @field_validator('value')
    @classmethod
    def validate_scope_value(cls, v, info):
        """Valide la valeur du scope selon son type."""
        scope_type = info.data.get('scope_type')
        
        if scope_type == ScopeType.domain:
            return validators.validate_domain(v)
        elif scope_type == ScopeType.ip_range:
            return validators.validate_ip_range(v)
        elif scope_type == ScopeType.hostname:
            return validators.validate_hostname(v)
        else:
            raise ValueError(f"Unknown scope type: {scope_type}")

class Scope(ScopeBase):
    id: UUID
    program_id: UUID
    
    model_config = ConfigDict(from_attributes=True)

class ProgramBase(BaseModel):
    name: str

class ProgramCreate(ProgramBase):
    @field_validator('name')
    @classmethod
    def validate_program_name(cls, v):
        """Valide et nettoie le nom du programme."""
        return validators.sanitize_string(v, max_length=200)

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

class ScanWithEvents(Scan):
    events: List[ScanEvent] = []

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
    status: VulnStatus = VulnStatus.open  # Default value to prevent validation errors

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

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: UUID
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
