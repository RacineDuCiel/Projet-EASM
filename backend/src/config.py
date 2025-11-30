"""
Configuration centralisée avec validation des variables d'environnement.
"""
import os
from typing import Optional


class ConfigurationError(Exception):
    """Exception levée quand une variable d'environnement requise est manquante."""
    pass


class Settings:
    """Classe de configuration centralisée."""
    
    # Environnement
    ENVIRONMENT: str
    
    # Sécurité
    SECRET_KEY: str
    
    # Base de données
    DATABASE_URL: str
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_DB: str
    
    # Redis
    REDIS_URL: str
    
    # Backend
    BACKEND_URL: str
    
    # Notifications
    DISCORD_WEBHOOK_URL: Optional[str]
    
    # Scan Configuration
    SCAN_PORTS: str
    HTTP_TIMEOUT: int
    
    def __init__(self):
        """Initialise et valide toutes les variables d'environnement."""
        # Environnement
        self.ENVIRONMENT = self._get_optional("ENVIRONMENT", "development")
        
        # Sécurité
        self.SECRET_KEY = self._get_required("SECRET_KEY")
        self._validate_secret_key()
        
        # Base de données
        self.DATABASE_URL = self._get_required("DATABASE_URL")
        self.POSTGRES_USER = self._get_optional("POSTGRES_USER", "easm_user")
        self.POSTGRES_PASSWORD = self._get_optional("POSTGRES_PASSWORD", "")
        self.POSTGRES_DB = self._get_optional("POSTGRES_DB", "easm_db")
        
        # Redis
        self.REDIS_URL = self._get_required("REDIS_URL")
        
        # Backend
        self.BACKEND_URL = self._get_optional("BACKEND_URL", "http://backend:8000")
        
        # Notifications
        self.DISCORD_WEBHOOK_URL = self._get_optional("DISCORD_WEBHOOK_URL", None)
        
        # Scan Configuration
        self.SCAN_PORTS = self._get_optional("SCAN_PORTS", "80,443,3000-3010,4200,5000-5010,8000-8010,8080-8090")
        self.HTTP_TIMEOUT = int(self._get_optional("HTTP_TIMEOUT", "30"))
        
        # Log de confirmation en mode développement
        if self.ENVIRONMENT == "development":
            print("Configuration loaded successfully")
            print(f"   - Environment: {self.ENVIRONMENT}")
            print(f"   - Database: {self._mask_url(self.DATABASE_URL)}")
            print(f"   - Redis: {self._mask_url(self.REDIS_URL)}")
    
    def _get_required(self, key: str) -> str:
        """Récupère une variable d'environnement requise."""
        value = os.getenv(key)
        if not value:
            raise ConfigurationError(
                f"Missing required environment variable: {key}\n"
                f"Please set it in your .env file or environment.\n"
                f"See .env.example for reference."
            )
        return value
    
    def _get_optional(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Récupère une variable d'environnement optionnelle."""
        return os.getenv(key, default)
    
    def _validate_secret_key(self):
        """Valide que la SECRET_KEY est suffisamment sécurisée."""
        if self.ENVIRONMENT == "production":
            if len(self.SECRET_KEY) < 32:
                raise ConfigurationError(
                    "SECRET_KEY must be at least 32 characters in production.\n"
                    "Generate one with: openssl rand -hex 32"
                )
            
            # Vérifier que ce n'est pas une valeur par défaut
            unsafe_defaults = [
                "supersecretkeychangeinprod",
                "changeme",
                "secret",
                "your-secret-key-here"
            ]
            if self.SECRET_KEY.lower() in unsafe_defaults:
                raise ConfigurationError(
                    "SECRET_KEY appears to be a default value. "
                    "Please generate a secure key with: openssl rand -hex 32"
                )
    
    def _mask_url(self, url: str) -> str:
        """Masque les credentials dans une URL pour le logging."""
        if "@" in url:
            # Format: protocol://user:pass@host:port/db
            parts = url.split("@")
            if "://" in parts[0]:
                protocol_user = parts[0].split("://")
                return f"{protocol_user[0]}://***:***@{parts[1]}"
        return url
    
    @property
    def is_production(self) -> bool:
        """Retourne True si l'environnement est production."""
        return self.ENVIRONMENT == "production"
    
    @property
    def is_development(self) -> bool:
        """Retourne True si l'environnement est développement."""
        return self.ENVIRONMENT == "development"


# Instance globale de configuration
try:
    settings = Settings()
except ConfigurationError as e:
    print(f"❌ Configuration Error: {e}")
    raise
