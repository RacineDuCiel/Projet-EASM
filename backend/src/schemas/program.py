from pydantic import BaseModel, ConfigDict, field_validator
from typing import List, Optional
from uuid import UUID
from datetime import datetime
from src.models.enums import ScopeType, ScanFrequency, ScanProfile
from src.core import validators


class ScopeBase(BaseModel):
    value: str


class ScopeCreate(ScopeBase):
    @field_validator('value')
    @classmethod
    def validate_asset_not_empty(cls, v):
        """Validation basique - le parsing se fait dans le CRUD."""
        if not v or not v.strip():
            raise ValueError("Asset value cannot be empty")
        return v.strip()


class Scope(BaseModel):
    id: UUID
    program_id: UUID
    scope_type: ScopeType
    value: str
    port: Optional[int] = None

    model_config = ConfigDict(from_attributes=True)


class ProgramBase(BaseModel):
    name: str
    discord_webhook_url: str | None = None
    scan_frequency: ScanFrequency = ScanFrequency.never
    # Scan configuration fields
    default_scan_profile: ScanProfile = ScanProfile.standard_assessment
    custom_ports: str | None = None
    nuclei_rate_limit: int | None = None
    nuclei_timeout: int | None = None
    # Automated monitoring configuration
    auto_scan_enabled: bool = False
    delta_scan_enabled: bool = False
    delta_scan_threshold_hours: int = 24


class ProgramCreate(ProgramBase):
    @classmethod
    def validate_program_name(cls, v):
        return validators.sanitize_string(v, max_length=200)


class ProgramUpdate(BaseModel):
    name: Optional[str] = None
    discord_webhook_url: Optional[str] = None
    scan_frequency: Optional[ScanFrequency] = None
    # Scan configuration fields
    default_scan_profile: Optional[ScanProfile] = None
    custom_ports: Optional[str] = None
    nuclei_rate_limit: Optional[int] = None
    nuclei_timeout: Optional[int] = None
    # Automated monitoring configuration
    auto_scan_enabled: Optional[bool] = None
    delta_scan_enabled: Optional[bool] = None
    delta_scan_threshold_hours: Optional[int] = None

    @field_validator('name')
    @classmethod
    def validate_program_name(cls, v):
        if v is None:
            return v
        return validators.sanitize_string(v, max_length=200)


class Program(ProgramBase):
    id: UUID
    discord_webhook_url: str | None = None
    scan_frequency: ScanFrequency
    # Scan configuration fields
    default_scan_profile: ScanProfile
    custom_ports: str | None = None
    nuclei_rate_limit: int | None = None
    nuclei_timeout: int | None = None
    # Automated monitoring configuration
    auto_scan_enabled: bool = False
    delta_scan_enabled: bool = False
    delta_scan_threshold_hours: int = 24
    created_at: datetime
    scopes: List[Scope] = []

    model_config = ConfigDict(from_attributes=True)
