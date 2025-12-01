import uuid
from sqlalchemy import Column, String, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from src.db.session import Base

class SystemLog(Base):
    __tablename__ = "system_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    level = Column(String, nullable=False, default="info") # info, warning, error
    message = Column(String, nullable=False)
    source = Column(String, nullable=False, default="system") # auth, system, scan, etc.
    user_id = Column(UUID(as_uuid=True), nullable=True) # Optional: who triggered the event
    created_at = Column(DateTime(timezone=True), server_default=func.now())
