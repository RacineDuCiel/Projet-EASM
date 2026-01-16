"""
Custom SQLAlchemy types for the EASM platform.
"""
from sqlalchemy import String, TypeDecorator

from src.core.encryption import encrypt_value, decrypt_value


class EncryptedString(TypeDecorator):
    """
    SQLAlchemy type that automatically encrypts/decrypts string values.

    Values are encrypted when stored in the database and automatically
    decrypted when retrieved. Uses Fernet symmetric encryption.

    Usage:
        api_key = Column(EncryptedString(500), nullable=True)
    """

    impl = String
    cache_ok = True

    def process_bind_param(self, value, dialect):
        """Encrypt the value before storing in the database."""
        if value is not None:
            return encrypt_value(value)
        return value

    def process_result_value(self, value, dialect):
        """Decrypt the value when retrieving from the database."""
        if value is not None:
            return decrypt_value(value)
        return value
