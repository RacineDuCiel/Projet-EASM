import uuid
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Integer, Text, Enum as SqlEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from src.db.session import Base
from .enums import AssetType, Severity, VulnStatus

class Asset(Base):
    __tablename__ = "assets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scope_id = Column(UUID(as_uuid=True), ForeignKey("scopes.id"), nullable=False)
    value = Column(String, nullable=False)
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
