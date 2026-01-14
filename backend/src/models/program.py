import uuid
from sqlalchemy import Column, String, DateTime, ForeignKey, Integer, Enum as SqlEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from src.db.session import Base
from .enums import ScopeType, ScanFrequency, ScanDepth

class Program(Base):
    __tablename__ = "programs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False)
    discord_webhook_url = Column(String, nullable=True)
    scan_frequency = Column(SqlEnum(ScanFrequency), default=ScanFrequency.never, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Scan configuration fields
    scan_depth = Column(SqlEnum(ScanDepth), default=ScanDepth.fast, nullable=False)
    custom_ports = Column(String, nullable=True)  # Custom ports override, e.g., "80,443,8080-8090"
    nuclei_rate_limit = Column(Integer, nullable=True)  # Override default Nuclei rate limit
    nuclei_timeout = Column(Integer, nullable=True)  # Override default Nuclei timeout (seconds)

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
