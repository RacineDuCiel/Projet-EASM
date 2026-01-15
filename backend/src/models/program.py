import uuid
from sqlalchemy import Column, String, DateTime, ForeignKey, Integer, Boolean, Enum as SqlEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from src.db.session import Base
from .enums import ScopeType, ScanFrequency, ScanProfile


class Program(Base):
    __tablename__ = "programs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False)
    discord_webhook_url = Column(String, nullable=True)
    scan_frequency = Column(SqlEnum(ScanFrequency), default=ScanFrequency.never, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Scan configuration fields
    default_scan_profile = Column(SqlEnum(ScanProfile), default=ScanProfile.standard_assessment, nullable=False)
    custom_ports = Column(String, nullable=True)  # Custom ports override, e.g., "80,443,8080-8090"
    nuclei_rate_limit = Column(Integer, nullable=True)  # Override default Nuclei rate limit
    nuclei_timeout = Column(Integer, nullable=True)  # Override default Nuclei timeout (seconds)
    delta_scan_threshold_hours = Column(Integer, default=24, nullable=False)  # For continuous monitoring

    # Passive Recon configuration
    passive_recon_enabled = Column(Boolean, default=True, nullable=False)
    enable_web_archive = Column(Boolean, default=True, nullable=False)
    enable_url_aggregation = Column(Boolean, default=True, nullable=False)
    enable_crawling = Column(Boolean, default=True, nullable=False)

    # External API keys (per-program, optional - falls back to global config)
    shodan_api_key = Column(String, nullable=True)
    securitytrails_api_key = Column(String, nullable=True)
    censys_api_id = Column(String, nullable=True)
    censys_api_secret = Column(String, nullable=True)

    scopes = relationship("Scope", back_populates="program", cascade="all, delete-orphan", lazy="selectin")

class Scope(Base):
    __tablename__ = "scopes"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    program_id = Column(UUID(as_uuid=True), ForeignKey("programs.id"), nullable=False)
    scope_type = Column(SqlEnum(ScopeType), nullable=False)
    value = Column(String, nullable=False)
    port = Column(Integer, nullable=True)  # Support pour la syntaxe Cible:Port

    program = relationship("Program", back_populates="scopes", lazy="selectin")
    scans = relationship("Scan", back_populates="scope", cascade="all, delete-orphan", lazy="selectin")
    assets = relationship("Asset", back_populates="scope", cascade="all, delete-orphan", lazy="selectin")
