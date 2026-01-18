from pydantic import BaseModel, ConfigDict
from typing import List, Optional
from uuid import UUID
from datetime import datetime
from src.models.enums import ScanProfile, ScanStatus, ScanPhase
from .asset import AssetCreate


class ScanBase(BaseModel):
    scan_profile: ScanProfile = ScanProfile.standard_assessment


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
    scan_profile: ScanProfile
    status: ScanStatus
    started_at: datetime
    completed_at: Optional[datetime] = None

    # Phase tracking
    selected_phases: Optional[List[str]] = None
    current_phase: Optional[ScanPhase] = None

    # Delta scanning
    is_delta_scan: bool = False
    delta_threshold_hours: Optional[int] = None

    # Statistics
    assets_scanned: int = 0
    assets_skipped: int = 0
    vulns_found: int = 0

    model_config = ConfigDict(from_attributes=True)


class ScanWithEvents(Scan):
    events: List[ScanEvent] = []


class ScanResult(BaseModel):
    status: ScanStatus
    assets: List[AssetCreate]


class ScanProfileInfo(BaseModel):
    """Information about a scan profile for frontend display."""
    profile: str
    display_name: str
    description: str
    phases: List[str]
    estimated_duration: str
    intensity: str


class ScanConfig(BaseModel):
    """Configuration passed to workers for scan execution."""
    scan_id: str
    target: str
    scan_profile: ScanProfile

    # Phase configuration
    phases: List[str]

    # Port configuration
    ports: str

    # Nuclei configuration
    nuclei_rate_limit: int
    nuclei_timeout: int
    nuclei_retries: int
    run_prioritized_templates: bool
    run_full_templates: bool

    # Passive recon
    passive_recon_enabled: bool
    passive_extended_enabled: bool

    # Delta scanning
    is_delta_scan: bool = False
    delta_threshold_hours: Optional[int] = None

    # API integrations
    enable_api_integrations: bool = False


class DeltaScanRequest(BaseModel):
    """Request schema for getting stale assets in delta scan mode."""
    asset_values: List[str]
    threshold_hours: int = 24


class MarkScannedRequest(BaseModel):
    """Request schema for marking assets as scanned."""
    asset_values: List[str]
