"""
Input validation utilities for EASM workers.
Prevents command injection and ensures data integrity.
"""
import re
import ipaddress
from urllib.parse import urlparse
from typing import Optional
from dataclasses import dataclass
from enum import Enum


class ValidationError(Exception):
    """Raised when input validation fails."""
    pass


class InputType(Enum):
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    PORT = "port"
    SUBDOMAIN = "subdomain"


@dataclass
class ValidationResult:
    is_valid: bool
    value: str
    error_message: Optional[str] = None
    sanitized_value: Optional[str] = None


DOMAIN_REGEX = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$')
IPV4_REGEX = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
IPV6_REGEX = re.compile(r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$')
URL_REGEX = re.compile(r'^https?://[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+(/[-a-zA-Z0-9_.%]*)*$')
PORT_REGEX = re.compile(r'^(\d{1,5}|[0-9]{1,5}-[0-9]{1,5})$')
SUBDOMAIN_REGEX = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$')


def validate_input(value: str, input_type: InputType, allow_wildcard: bool = False) -> ValidationResult:
    """
    Validate and sanitize input based on type.
    
    Args:
        value: The value to validate
        input_type: Type of input expected
        allow_wildcard: Whether to allow wildcard patterns (for subdomain enumeration)
    
    Returns:
        ValidationResult with validation status and sanitized value
    """
    if not value:
        return ValidationResult(
            is_valid=False,
            value=value,
            error_message=f"Empty value for type {input_type.value}"
        )
    
    value = value.strip()
    
    if input_type == InputType.DOMAIN:
        return _validate_domain(value, allow_wildcard)
    elif input_type == InputType.IP:
        return _validate_ip(value)
    elif input_type == InputType.URL:
        return _validate_url(value)
    elif input_type == InputType.PORT:
        return _validate_port(value)
    elif input_type == InputType.SUBDOMAIN:
        return _validate_subdomain(value, allow_wildcard)
    
    return ValidationResult(
        is_valid=False,
        value=value,
        error_message=f"Unknown input type: {input_type}"
    )


def _validate_domain(value: str, allow_wildcard: bool) -> ValidationResult:
    if allow_wildcard and value.startswith('*.'):
        value = value[2:]
    
    if len(value) > 253:
        return ValidationResult(
            is_valid=False,
            value=value,
            error_message="Domain name exceeds maximum length of 253 characters"
        )
    
    if not DOMAIN_REGEX.match(value):
        return ValidationResult(
            is_valid=False,
            value=value,
            error_message=f"Invalid domain format: {value}"
        )
    
    return ValidationResult(
        is_valid=True,
        value=value,
        sanitized_value=value.lower()
    )


def _validate_ip(value: str) -> ValidationResult:
    """
    Validate IP address using stdlib ipaddress module.
    Supports both IPv4 and IPv6, including compressed formats (::1, 2001:db8::1).
    """
    try:
        # ipaddress.ip_address handles both IPv4 and IPv6, including compressed formats
        ip_obj = ipaddress.ip_address(value)
        # Normalize the IP address (expands IPv6, removes leading zeros)
        normalized = str(ip_obj)
        return ValidationResult(
            is_valid=True,
            value=value,
            sanitized_value=normalized
        )
    except ValueError:
        return ValidationResult(
            is_valid=False,
            value=value,
            error_message=f"Invalid IP address format: {value}"
        )


def _validate_url(value: str) -> ValidationResult:
    """
    Validate URL using urllib.parse for comprehensive format support.
    Supports ports, query strings, fragments, underscores in hostnames.
    """
    try:
        parsed = urlparse(value)
        
        # Must have http or https scheme
        if parsed.scheme not in ('http', 'https'):
            return ValidationResult(
                is_valid=False,
                value=value,
                error_message=f"URL must use http or https scheme: {value}"
            )
        
        # Must have a valid netloc (hostname)
        if not parsed.netloc:
            return ValidationResult(
                is_valid=False,
                value=value,
                error_message=f"URL must have a valid hostname: {value}"
            )
        
        # Basic hostname validation (no spaces, control chars)
        hostname = parsed.hostname or ''
        if not hostname or ' ' in hostname or any(ord(c) < 32 for c in hostname):
            return ValidationResult(
                is_valid=False,
                value=value,
                error_message=f"Invalid hostname in URL: {value}"
            )
        
        return ValidationResult(
            is_valid=True,
            value=value,
            sanitized_value=value
        )
    except Exception:
        return ValidationResult(
            is_valid=False,
            value=value,
            error_message=f"Invalid URL format: {value}"
        )


def _validate_port(value: str) -> ValidationResult:
    if PORT_REGEX.match(value):
        if '-' in value:
            start, end = value.split('-')
            if 1 <= int(start) <= 65535 and 1 <= int(end) <= 65535:
                return ValidationResult(is_valid=True, value=value)
        else:
            port = int(value)
            if 1 <= port <= 65535:
                return ValidationResult(is_valid=True, value=value, sanitized_value=str(port))
    
    return ValidationResult(
        is_valid=False,
        value=value,
        error_message=f"Invalid port or port range: {value}"
    )


def _validate_subdomain(value: str, allow_wildcard: bool) -> ValidationResult:
    return _validate_domain(value, allow_wildcard)


def sanitize_for_command(value: str) -> str:
    """
    Sanitize a value to prevent command injection.
    Removes or escapes potentially dangerous characters.
    """
    dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '{', '}', '[', ']', 
                       '<', '>', '!', '#', '*', '?', '~', '"', "'", '\\', '\n', '\r']
    
    sanitized = value
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, '')
    
    sanitized = sanitized.strip()
    
    if len(sanitized) > 500:
        sanitized = sanitized[:500]
    
    return sanitized


def is_safe_for_subprocess(value: str) -> bool:
    """
    Quick check if a value is safe to use in subprocess arguments.
    """
    result = validate_input(value, InputType.DOMAIN)
    return result.is_valid
