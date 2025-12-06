import uuid
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Integer, Text, Enum as SqlEnum, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from src.db.session import Base
from .enums import AssetType, Severity, VulnStatus


class Asset(Base):
    """
    Represents a discovered asset (subdomain, IP, etc.) within a scope.
    """
    __tablename__ = "assets"
    __table_args__ = (
        Index('ix_assets_scope_id', 'scope_id'),
        Index('ix_assets_value', 'value'),
        Index('ix_assets_scope_value', 'scope_id', 'value'),  # Composite for unique lookups
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scope_id = Column(UUID(as_uuid=True), ForeignKey("scopes.id"), nullable=False, index=True)
    value = Column(String, nullable=False, index=True)
    asset_type = Column(SqlEnum(AssetType), nullable=False)
    is_active = Column(Boolean, default=True)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships - using selectin for eager loading when accessed
    scope = relationship("Scope", back_populates="assets", lazy="selectin")
    services = relationship("Service", back_populates="asset", cascade="all, delete-orphan", lazy="selectin")
    vulnerabilities = relationship("Vulnerability", back_populates="asset", cascade="all, delete-orphan", lazy="selectin")


class Service(Base):
    """
    Represents a discovered service (port/protocol) on an asset.
    """
    __tablename__ = "services"
    __table_args__ = (
        Index('ix_services_asset_id', 'asset_id'),
        Index('ix_services_port_protocol', 'asset_id', 'port', 'protocol'),  # For dedup lookups
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=False, index=True)
    port = Column(Integer, nullable=False)
    protocol = Column(String, default="tcp")
    service_name = Column(String, nullable=True)
    banner = Column(Text, nullable=True)

    asset = relationship("Asset", back_populates="services", lazy="selectin")
    vulnerabilities = relationship("Vulnerability", back_populates="service", lazy="selectin")


class Vulnerability(Base):
    """
    Represents a discovered vulnerability on an asset.
    """
    __tablename__ = "vulnerabilities"
    __table_args__ = (
        Index('ix_vulnerabilities_asset_id', 'asset_id'),
        Index('ix_vulnerabilities_severity', 'severity'),
        Index('ix_vulnerabilities_status', 'status'),
        Index('ix_vulnerabilities_asset_title', 'asset_id', 'title'),  # For dedup lookups
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=False, index=True)
    service_id = Column(UUID(as_uuid=True), ForeignKey("services.id"), nullable=True)
    title = Column(String, nullable=False, index=True)
    severity = Column(SqlEnum(Severity), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(SqlEnum(VulnStatus), default=VulnStatus.open)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    asset = relationship("Asset", back_populates="vulnerabilities", lazy="selectin")
    service = relationship("Service", back_populates="vulnerabilities", lazy="selectin")
