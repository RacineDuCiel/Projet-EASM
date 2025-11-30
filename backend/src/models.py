import uuid
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Integer, Text, Enum as SqlEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum
from .database import Base

class ScopeType(str, enum.Enum):
    domain = "domain"
    ip_range = "ip_range"
    hostname = "hostname"  # Pour services internes (Docker, intranet, etc.)

class ScanType(str, enum.Enum):
    passive = "passive"
    active = "active"
    full = "full"

class ScanStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"

class AssetType(str, enum.Enum):
    subdomain = "subdomain"
    ip = "ip"

class Severity(str, enum.Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

class VulnStatus(str, enum.Enum):
    open = "open"
    fixed = "fixed"
    false_positive = "false_positive"

class Program(Base):
    __tablename__ = "programs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    scopes = relationship("Scope", back_populates="program", cascade="all, delete-orphan", lazy="selectin")

class Scope(Base):
    __tablename__ = "scopes"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    program_id = Column(UUID(as_uuid=True), ForeignKey("programs.id"), nullable=False)
    scope_type = Column(SqlEnum(ScopeType), nullable=False)
    value = Column(String, nullable=False) # e.g. "example.com"

    program = relationship("Program", back_populates="scopes", lazy="selectin")
    scans = relationship("Scan", back_populates="scope", cascade="all, delete-orphan", lazy="selectin")
    assets = relationship("Asset", back_populates="scope", cascade="all, delete-orphan", lazy="selectin")

class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scope_id = Column(UUID(as_uuid=True), ForeignKey("scopes.id"), nullable=False)
    scan_type = Column(SqlEnum(ScanType), nullable=False)
    status = Column(SqlEnum(ScanStatus), default=ScanStatus.pending)
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)

    scope = relationship("Scope", back_populates="scans", lazy="selectin")
    events = relationship("ScanEvent", back_populates="scan", cascade="all, delete-orphan", lazy="selectin", order_by="ScanEvent.created_at")

class ScanEvent(Base):
    __tablename__ = "scan_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    message = Column(String, nullable=False)
    severity = Column(String, default="info") # info, warning, error
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    scan = relationship("Scan", back_populates="events", lazy="selectin")

class Asset(Base):
    __tablename__ = "assets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scope_id = Column(UUID(as_uuid=True), ForeignKey("scopes.id"), nullable=False)
    value = Column(String, nullable=False) # e.g. "sub.example.com"
    asset_type = Column(SqlEnum(AssetType), nullable=False)
    is_active = Column(Boolean, default=True)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now())

    scope = relationship("Scope", back_populates="assets", lazy="selectin")
    services = relationship("Service", back_populates="asset", cascade="all, delete-orphan", lazy="selectin")
    vulnerabilities = relationship("Vulnerability", back_populates="asset", cascade="all, delete-orphan", lazy="selectin")

class Service(Base):
    __tablename__ = "services"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String, default="tcp")
    service_name = Column(String, nullable=True)
    banner = Column(Text, nullable=True)

    asset = relationship("Asset", back_populates="services", lazy="selectin")
    vulnerabilities = relationship("Vulnerability", back_populates="service", lazy="selectin")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    service_id = Column(UUID(as_uuid=True), ForeignKey("services.id"), nullable=True)
    title = Column(String, nullable=False)
    severity = Column(SqlEnum(Severity), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(SqlEnum(VulnStatus), default=VulnStatus.open)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    asset = relationship("Asset", back_populates="vulnerabilities", lazy="selectin")
    service = relationship("Service", back_populates="vulnerabilities", lazy="selectin")

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
