"""
Encryption utilities for sensitive data storage.

Uses Fernet symmetric encryption derived from SECRET_KEY.
"""
import base64
import hashlib
import logging
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

_fernet: Optional[Fernet] = None


def _get_encryption_key() -> bytes:
    """Derive a Fernet-compatible key from SECRET_KEY."""
    from src.core.config import settings

    # Derive a 32-byte key using SHA-256, then base64-encode for Fernet
    key = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
    return base64.urlsafe_b64encode(key)


def get_fernet() -> Fernet:
    """Get or create the Fernet instance for encryption/decryption."""
    global _fernet
    if _fernet is None:
        _fernet = Fernet(_get_encryption_key())
    return _fernet


def encrypt_value(value: Optional[str]) -> Optional[str]:
    """
    Encrypt a string value.

    Args:
        value: The plaintext string to encrypt

    Returns:
        The encrypted value as a base64-encoded string, or None if input is None/empty
    """
    if not value:
        return value
    try:
        encrypted = get_fernet().encrypt(value.encode())
        return encrypted.decode()
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        raise


def decrypt_value(encrypted: Optional[str]) -> Optional[str]:
    """
    Decrypt an encrypted string value.

    Args:
        encrypted: The encrypted base64-encoded string

    Returns:
        The decrypted plaintext string, or None if input is None/empty
    """
    if not encrypted:
        return encrypted
    try:
        decrypted = get_fernet().decrypt(encrypted.encode())
        return decrypted.decode()
    except InvalidToken:
        logger.warning("Failed to decrypt value - invalid token (key may have changed)")
        return None
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        return None


def reset_fernet() -> None:
    """Reset the Fernet instance (useful for testing)."""
    global _fernet
    _fernet = None
