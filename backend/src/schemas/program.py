from pydantic import BaseModel, ConfigDict, field_validator
from typing import List
from uuid import UUID
from datetime import datetime
from src.models.enums import ScopeType
from src.core import validators

class ScopeBase(BaseModel):
    scope_type: ScopeType
    value: str

class ScopeCreate(ScopeBase):
    @field_validator('value')
    @classmethod
    def validate_scope_value(cls, v, info):
        scope_type = info.data.get('scope_type')
        if scope_type == ScopeType.domain:
            return validators.validate_domain(v)
        elif scope_type == ScopeType.ip_range:
            return validators.validate_ip_range(v)
        elif scope_type == ScopeType.hostname:
            return validators.validate_hostname(v)
        else:
            raise ValueError(f"Unknown scope type: {scope_type}")

class Scope(ScopeBase):
    id: UUID
    program_id: UUID
    
    model_config = ConfigDict(from_attributes=True)

class ProgramBase(BaseModel):
    name: str

class ProgramCreate(ProgramBase):
    @field_validator('name')
    @classmethod
    def validate_program_name(cls, v):
        return validators.sanitize_string(v, max_length=200)

class Program(ProgramBase):
    id: UUID
    created_at: datetime
    scopes: List[Scope] = []

    model_config = ConfigDict(from_attributes=True)
