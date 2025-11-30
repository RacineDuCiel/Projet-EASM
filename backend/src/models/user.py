import uuid
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Enum as SqlEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from src.db.session import Base
from .enums import UserRole

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    role = Column(SqlEnum(UserRole), default=UserRole.user, nullable=False)
    program_id = Column(UUID(as_uuid=True), ForeignKey("programs.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    program = relationship("Program", backref="users", lazy="selectin")
