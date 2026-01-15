from pydantic import BaseModel, ConfigDict
from typing import List, Optional
from uuid import UUID
from datetime import datetime
from src.models.enums import AssetType, AssetCriticality, Severity, VulnStatus

class ServiceBase(BaseModel):
    port: int
    protocol: str
    service_name: Optional[str] = None
    banner: Optional[str] = None
    # Technology detection fields
    technologies: Optional[List[str]] = None
    web_server: Optional[str] = None
    waf_detected: Optional[str] = None
    tls_version: Optional[str] = None
    response_time_ms: Optional[int] = None

class ServiceCreate(ServiceBase):
    pass

class ServiceUpdate(BaseModel):
    """For updating service with tech detection results."""
    technologies: Optional[List[str]] = None
    web_server: Optional[str] = None
    waf_detected: Optional[str] = None
    tls_version: Optional[str] = None
    response_time_ms: Optional[int] = None

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

class VulnerabilityStreamCreate(BaseModel):
    """Schema pour le streaming temps réel de vulnérabilités."""
    asset_value: str  # La cible (domain/IP/hostname)
    asset_type: AssetType  # Type d'asset
    title: str
    severity: Severity
    description: Optional[str] = None
    port: Optional[int] = None  # Port associé si applicable
    service_name: Optional[str] = None


class TechDetectionResult(BaseModel):
    """Result from httpx tech detection task."""
    asset_value: str
    port: int
    technologies: List[str] = []
    web_server: Optional[str] = None
    waf_detected: Optional[str] = None
    tls_version: Optional[str] = None
    response_time_ms: Optional[int] = None

class VulnerabilityUpdate(BaseModel):
    status: Optional[VulnStatus] = None
    severity: Optional[Severity] = None
    description: Optional[str] = None

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


class AssetUpdate(BaseModel):
    """For updating asset properties including criticality."""
    is_active: Optional[bool] = None
    criticality: Optional[AssetCriticality] = None


class Asset(AssetBase):
    id: UUID
    scope_id: UUID
    first_seen: datetime
    last_seen: datetime

    # Criticality and scan tracking
    criticality: AssetCriticality = AssetCriticality.unclassified
    last_scanned_at: Optional[datetime] = None
    scan_count: int = 0

    services: List[Service] = []
    vulnerabilities: List[Vulnerability] = []

    model_config = ConfigDict(from_attributes=True)
