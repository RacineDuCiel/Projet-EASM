"""
Validators pour les entrées utilisateur.
Sécurise l'application contre les injections et formats invalides.
"""
import re
import ipaddress
from typing import Optional
from pydantic import validator


# Regex pour domaines valides (RFC 1035)
DOMAIN_REGEX = re.compile(
    r'^(?=.{1,253}$)'  # Longueur totale max 253 caractères
    r'(?!-)'  # Ne commence pas par un tiret
    r'([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*'  # Sous-domaines
    r'[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?'  # Domaine principal
    r'$',
    re.IGNORECASE
)

# Liste de caractères dangereux interdits
DANGEROUS_CHARS = ['<', '>', '&', '"', "'", ';', '`', '|', '$', '(', ')', '{', '}', '[', ']']


def validate_domain(domain: str) -> str:
    """
    Valide qu'un domaine est bien formé et sécurisé.
    
    Args:
        domain: Le domaine à valider
        
    Returns:
        Le domaine en minuscules si valide
        
    Raises:
        ValueError: Si le domaine est invalide
    """
    if not domain:
        raise ValueError("Domain cannot be empty")
    
    # Nettoyer les espaces
    domain = domain.strip().lower()
    
    # Vérifier la longueur
    if len(domain) > 253:
        raise ValueError("Domain is too long (max 253 characters)")
    
    if len(domain) < 3:
        raise ValueError("Domain is too short (min 3 characters)")
    
    # Vérifier les caractères dangereux
    for char in DANGEROUS_CHARS:
        if char in domain:
            raise ValueError(f"Domain contains invalid character: {char}")
    
    # Valider le format avec regex
    if not DOMAIN_REGEX.match(domain):
        raise ValueError("Invalid domain format")
    
    # Vérifier qu'il y a au moins un point (TLD)
    if '.' not in domain:
        raise ValueError("Domain must include a TLD (e.g., .com, .org)")
    
    # Vérifier qu'il ne se termine pas par un point
    if domain.endswith('.'):
        raise ValueError("Domain cannot end with a dot")
    
    # Vérifier les doubles tirets consécutifs (sauf xn-- pour IDN)
    if '--' in domain and not domain.startswith('xn--'):
        parts = domain.split('.')
        for part in parts:
            if '--' in part and not part.startswith('xn--'):
                raise ValueError("Domain contains invalid double hyphens")
    
    return domain


def validate_ip_address(ip: str) -> str:
    """
    Valide qu'une adresse IP est bien formée.
    
    Args:
        ip: L'adresse IP à valider
        
    Returns:
        L'adresse IP si valide
        
    Raises:
        ValueError: Si l'IP est invalide
    """
    if not ip:
        raise ValueError("IP address cannot be empty")
    
    ip = ip.strip()
    
    try:
        # Tente de parser comme IPv4 ou IPv6
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        raise ValueError(f"Invalid IP address format: {ip}")


def validate_ip_range(ip_range: str) -> str:
    """
    Valide qu'une plage IP (CIDR) est bien formée.
    
    Args:
        ip_range: La plage IP à valider (e.g., "192.168.1.0/24")
        
    Returns:
        La plage IP si valide
        
    Raises:
        ValueError: Si la plage est invalide
    """
    if not ip_range:
        raise ValueError("IP range cannot be empty")
    
    ip_range = ip_range.strip()
    
    try:
        # Tente de parser comme réseau IPv4 ou IPv6
        network = ipaddress.ip_network(ip_range, strict=False)
        return str(network)
    except ValueError:
        raise ValueError(f"Invalid IP range format: {ip_range}")


def validate_hostname(hostname: str) -> str:
    """
    Valide qu'un hostname est bien formé (pour services internes, Docker, etc.).
    Plus permissif que validate_domain car ne requiert pas de TLD.
    
    Args:
        hostname: Le hostname à valider (e.g., "juice-shop", "mysql-server")
        
    Returns:
        Le hostname en minuscules si valide
        
    Raises:
        ValueError: Si le hostname est invalide
    """
    if not hostname:
        raise ValueError("Hostname cannot be empty")
    
    # Nettoyer les espaces
    hostname = hostname.strip().lower()
    
    # Vérifier la longueur
    if len(hostname) > 253:
        raise ValueError("Hostname is too long (max 253 characters)")
    
    if len(hostname) < 1:
        raise ValueError("Hostname cannot be empty")
    
    # Vérifier les caractères dangereux
    for char in DANGEROUS_CHARS:
        if char in hostname:
            raise ValueError(f"Hostname contains invalid character: {char}")
    
    # Regex simple pour hostname : lettres, chiffres, tirets, points
    # Peut être un simple mot (docker service) ou FQDN interne
    hostname_regex = re.compile(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$')
    
    if not hostname_regex.match(hostname):
        raise ValueError("Invalid hostname format. Use only letters, numbers, hyphens, and dots.")
    
    # Ne peut pas commencer ou finir par un tiret ou point
    if hostname.startswith('-') or hostname.endswith('-'):
        raise ValueError("Hostname cannot start or end with a hyphen")
    
    if hostname.startswith('.') or hostname.endswith('.'):
        raise ValueError("Hostname cannot start or end with a dot")
    
    return hostname


def validate_port(port: int) -> int:
    """
    Valide qu'un numéro de port est dans la plage valide.
    
    Args:
        port: Le numéro de port à valider
        
    Returns:
        Le port si valide
        
    Raises:
        ValueError: Si le port est invalide
    """
    if not isinstance(port, int):
        raise ValueError("Port must be an integer")
    
    if port < 1 or port > 65535:
        raise ValueError("Port must be between 1 and 65535")
    
    return port


def validate_scan_type(scan_type: str) -> str:
    """
    Valide qu'un type de scan est autorisé.
    
    Args:
        scan_type: Le type de scan
        
    Returns:
        Le type de scan si valide
        
    Raises:
        ValueError: Si le type est invalide
    """
    valid_types = ["passive", "active", "full"]
    
    if scan_type not in valid_types:
        raise ValueError(f"Invalid scan type. Must be one of: {', '.join(valid_types)}")
    
    return scan_type


def sanitize_string(value: str, max_length: int = 1000) -> str:
    """
    Nettoie une chaîne de caractères pour éviter les injections.
    
    Args:
        value: La chaîne à nettoyer
        max_length: Longueur maximale autorisée
        
    Returns:
        La chaîne nettoyée
        
    Raises:
        ValueError: Si la chaîne est trop longue
    """
    if not value:
        return ""
    
    # Limiter la taille
    if len(value) > max_length:
        raise ValueError(f"String too long (max {max_length} characters)")
    
    # Supprimer les caractères de contrôle
    value = ''.join(char for char in value if ord(char) >= 32 or char in '\n\r\t')
    
    return value.strip()


# Pydantic validators pour utilisation dans les schemas

class ValidatedDomain:
    """Mixin pour validation de domaine dans Pydantic models."""
    
    @validator('value')
    def validate_domain_field(cls, v):
        """Valide le champ 'value' comme domaine."""
        return validate_domain(v)


class ValidatedIPRange:
    """Mixin pour validation de plage IP dans Pydantic models."""
    
    @validator('value')
    def validate_ip_range_field(cls, v):
        """Valide le champ 'value' comme plage IP."""
        return validate_ip_range(v)
