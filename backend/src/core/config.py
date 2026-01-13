from typing import Optional, List
from pydantic_settings import BaseSettings
from pydantic import field_validator

class Settings(BaseSettings):
    # Environment
    ENVIRONMENT: str = "development"
    
    # Security
    SECRET_KEY: str
    FIRST_SUPERUSER: str = "admin"
    FIRST_SUPERUSER_PASSWORD: str = "ChangeMe123!"
    
    # Database
    POSTGRES_USER: str = "easm_user"
    POSTGRES_PASSWORD: str = "easm_password"
    POSTGRES_DB: str = "easm_db"
    DATABASE_URL: str
    
    # Redis
    REDIS_URL: str
    
    # Backend
    BACKEND_URL: str = "http://backend:8000"
    
    # Notifications
    DISCORD_WEBHOOK_URL: Optional[str] = None
    
    # Scan Configuration
    SCAN_PORTS: str = "80,443,3000-3010,4200,5000-5010,8000-8010,8080-8090"
    HTTP_TIMEOUT: int = 30
    
    @field_validator("SECRET_KEY")
    @classmethod
    def validate_secret_key(cls, v, info):
        values = info.data
        if values.get("ENVIRONMENT") == "production":
            if len(v) < 32:
                raise ValueError("SECRET_KEY must be at least 32 characters in production.")
            unsafe_defaults = ["changeme", "secret", "your-secret-key-here"]
            if any(default in v.lower() for default in unsafe_defaults):
                raise ValueError("SECRET_KEY appears to be a default value.")
        return v

    class Config:
        case_sensitive = True
        extra = "ignore"  # Ignore les variables d'env non définies dans Settings

settings = Settings()
