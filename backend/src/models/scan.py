import uuid
from sqlalchemy import Column, String, DateTime, ForeignKey, Integer, Boolean, Enum as SqlEnum
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from src.db.session import Base
from .enums import ScanProfile, ScanStatus, ScanPhase


class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scope_id = Column(UUID(as_uuid=True), ForeignKey("scopes.id"), nullable=False)

    # Profile-based scanning
    scan_profile = Column(SqlEnum(ScanProfile), default=ScanProfile.standard_assessment, nullable=False)
    status = Column(SqlEnum(ScanStatus), default=ScanStatus.pending)
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Phase tracking
    selected_phases = Column(ARRAY(String), nullable=True)
    current_phase = Column(SqlEnum(ScanPhase), nullable=True)

    # Delta scanning
    is_delta_scan = Column(Boolean, default=False, nullable=False)
    delta_threshold_hours = Column(Integer, nullable=True)

    # Statistics
    assets_scanned = Column(Integer, default=0, nullable=False)
    assets_skipped = Column(Integer, default=0, nullable=False)
    vulns_found = Column(Integer, default=0, nullable=False)

    scope = relationship("Scope", back_populates="scans", lazy="selectin")
    events = relationship("ScanEvent", back_populates="scan", cascade="all, delete-orphan", lazy="selectin", order_by="ScanEvent.created_at")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", lazy="selectin")

class ScanEvent(Base):
    __tablename__ = "scan_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    message = Column(String, nullable=False)
    severity = Column(String, default="info")
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    scan = relationship("Scan", back_populates="events", lazy="selectin")
