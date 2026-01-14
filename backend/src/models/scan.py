import uuid
from sqlalchemy import Column, String, DateTime, ForeignKey, Enum as SqlEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from src.db.session import Base
from .enums import ScanType, ScanStatus, ScanDepth

class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scope_id = Column(UUID(as_uuid=True), ForeignKey("scopes.id"), nullable=False)
    scan_type = Column(SqlEnum(ScanType), nullable=False)
    scan_depth = Column(SqlEnum(ScanDepth), default=ScanDepth.fast, nullable=False)
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
    severity = Column(String, default="info")
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    scan = relationship("Scan", back_populates="events", lazy="selectin")
