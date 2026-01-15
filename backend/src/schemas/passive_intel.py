"""
Pydantic schemas for Passive Intelligence data.
Used for API request/response validation and serialization.
"""
from pydantic import BaseModel, ConfigDict
from typing import List, Optional, Dict, Any
from uuid import UUID
from datetime import datetime


# ============================================================================
# DNS Records
# ============================================================================

class DNSRecordBase(BaseModel):
    record_type: str  # A, AAAA, MX, TXT, NS, SOA, CNAME, PTR
    record_value: str
    ttl: Optional[int] = None
    priority: Optional[int] = None


class DNSRecordCreate(DNSRecordBase):
    pass


class DNSRecord(DNSRecordBase):
    id: UUID
    asset_id: UUID
    first_seen: datetime
    last_seen: datetime

    model_config = ConfigDict(from_attributes=True)


class DNSRecordsPayload(BaseModel):
    """Payload for receiving DNS records from workers."""
    asset_value: str
    records: List[DNSRecordCreate]


# ============================================================================
# WHOIS Records
# ============================================================================

class WHOISRecordBase(BaseModel):
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    name_servers: Optional[str] = None  # JSON array
    registrant_org: Optional[str] = None
    registrant_country: Optional[str] = None
    registrant_email: Optional[str] = None
    dnssec: Optional[bool] = None
    raw_data: Optional[str] = None


class WHOISRecordCreate(WHOISRecordBase):
    pass


class WHOISRecord(WHOISRecordBase):
    id: UUID
    asset_id: UUID
    collected_at: datetime

    model_config = ConfigDict(from_attributes=True)


class WHOISPayload(BaseModel):
    """Payload for receiving WHOIS data from workers."""
    asset_value: str
    whois_data: WHOISRecordCreate


# ============================================================================
# Certificates
# ============================================================================

class CertificateBase(BaseModel):
    serial_number: Optional[str] = None
    issuer_cn: Optional[str] = None
    issuer_org: Optional[str] = None
    subject_cn: Optional[str] = None
    subject_alt_names: Optional[str] = None  # JSON array
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    signature_algorithm: Optional[str] = None
    key_algorithm: Optional[str] = None
    key_size: Optional[int] = None
    is_self_signed: Optional[bool] = None
    is_expired: Optional[bool] = None
    is_wildcard: Optional[bool] = None
    fingerprint_sha256: Optional[str] = None
    tls_version: Optional[str] = None
    source: Optional[str] = None  # "crt.sh", "tlsx", "censys"


class CertificateCreate(CertificateBase):
    pass


class Certificate(CertificateBase):
    id: UUID
    asset_id: UUID
    service_id: Optional[UUID] = None
    collected_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CertificatesPayload(BaseModel):
    """Payload for receiving certificates from workers."""
    asset_value: str
    certificates: List[CertificateCreate]


class TLSCertPayload(BaseModel):
    """Payload for receiving a single TLS cert from tlsx."""
    asset_value: str
    certificate: CertificateCreate


# ============================================================================
# ASN Information
# ============================================================================

class ASNInfoBase(BaseModel):
    ip_address: str
    asn_number: Optional[int] = None
    asn_name: Optional[str] = None
    asn_description: Optional[str] = None
    asn_country: Optional[str] = None
    bgp_prefix: Optional[str] = None
    rir: Optional[str] = None


class ASNInfoCreate(ASNInfoBase):
    pass


class ASNInfo(ASNInfoBase):
    id: UUID
    asset_id: UUID
    collected_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ASNPayload(BaseModel):
    """Payload for receiving ASN data from workers."""
    asset_value: str
    asn_data: ASNInfoCreate


# ============================================================================
# Historical URLs
# ============================================================================

class HistoricalURLBase(BaseModel):
    url: str
    source: Optional[str] = None  # "wayback", "gau", "commoncrawl"
    archived_date: Optional[str] = None
    status_code: Optional[int] = None
    content_type: Optional[str] = None


class HistoricalURLCreate(HistoricalURLBase):
    pass


class HistoricalURL(HistoricalURLBase):
    id: UUID
    asset_id: UUID
    collected_at: datetime

    model_config = ConfigDict(from_attributes=True)


class HistoricalURLsPayload(BaseModel):
    """Payload for receiving historical URLs from workers."""
    asset_value: str
    urls: List[Dict[str, Any]]  # Flexible format from different sources
    source: Optional[str] = None


# ============================================================================
# Security Headers
# ============================================================================

class SecurityHeaderBase(BaseModel):
    url: Optional[str] = None
    content_security_policy: Optional[str] = None
    strict_transport_security: Optional[str] = None
    x_frame_options: Optional[str] = None
    x_content_type_options: Optional[str] = None
    x_xss_protection: Optional[str] = None
    referrer_policy: Optional[str] = None
    permissions_policy: Optional[str] = None
    missing_headers: Optional[str] = None  # JSON array
    score: Optional[int] = None
    grade: Optional[str] = None


class SecurityHeaderCreate(SecurityHeaderBase):
    pass


class SecurityHeader(SecurityHeaderBase):
    id: UUID
    asset_id: UUID
    service_id: Optional[UUID] = None
    collected_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SecurityHeadersPayload(BaseModel):
    """Payload for receiving security headers from workers."""
    asset_value: str
    headers: SecurityHeaderCreate


# ============================================================================
# Favicon Hash
# ============================================================================

class FaviconHashBase(BaseModel):
    mmh3_hash: Optional[str] = None
    md5_hash: Optional[str] = None
    sha256_hash: Optional[str] = None
    favicon_url: Optional[str] = None
    favicon_size: Optional[int] = None


class FaviconHashCreate(FaviconHashBase):
    pass


class FaviconHash(FaviconHashBase):
    id: UUID
    asset_id: UUID
    collected_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FaviconPayload(BaseModel):
    """Payload for receiving favicon hash from workers."""
    asset_value: str
    favicon_hash: FaviconHashCreate


# ============================================================================
# Shodan Data
# ============================================================================

class ShodanDataBase(BaseModel):
    ip_address: str
    open_ports: Optional[str] = None  # JSON array
    hostnames: Optional[str] = None  # JSON array
    domains: Optional[str] = None  # JSON array
    os: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    country: Optional[str] = None
    latitude: Optional[str] = None
    longitude: Optional[str] = None
    last_update: Optional[str] = None
    vulns: Optional[str] = None  # JSON array
    tags: Optional[str] = None  # JSON array
    raw_data: Optional[str] = None


class ShodanDataCreate(ShodanDataBase):
    pass


class ShodanData(ShodanDataBase):
    id: UUID
    asset_id: UUID
    collected_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ShodanPayload(BaseModel):
    """Payload for receiving Shodan data from workers."""
    asset_value: str
    shodan_data: ShodanDataCreate


# ============================================================================
# Crawled Endpoints
# ============================================================================

class CrawledEndpointBase(BaseModel):
    url: str
    method: str = "GET"
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    parameters: Optional[str] = None  # JSON array
    source: Optional[str] = None  # "katana", "gau", "robots"
    is_js_file: bool = False
    is_api_endpoint: bool = False


class CrawledEndpointCreate(CrawledEndpointBase):
    pass


class CrawledEndpoint(CrawledEndpointBase):
    id: UUID
    asset_id: UUID
    collected_at: datetime

    model_config = ConfigDict(from_attributes=True)


class EndpointsPayload(BaseModel):
    """Payload for receiving crawled endpoints from workers."""
    asset_value: str
    endpoints: List[Dict[str, Any]]


# ============================================================================
# SecurityTrails Data
# ============================================================================

class SecurityTrailsPayload(BaseModel):
    """Payload for receiving SecurityTrails data from workers."""
    asset_value: str
    securitytrails_data: Dict[str, Any]


# ============================================================================
# Censys Data
# ============================================================================

class CensysPayload(BaseModel):
    """Payload for receiving Censys data from workers."""
    asset_value: str
    censys_data: Dict[str, Any]


# ============================================================================
# HackerTarget Data
# ============================================================================

class HackerTargetPayload(BaseModel):
    """Payload for receiving HackerTarget data from workers."""
    asset_value: str
    hackertarget_data: Dict[str, Any]


# ============================================================================
# Reverse DNS
# ============================================================================

class ReverseDNSPayload(BaseModel):
    """Payload for receiving reverse DNS data from workers."""
    asset_value: str
    ip_address: str
    ptr_hostname: Optional[str] = None


# ============================================================================
# Summary / Aggregated Views
# ============================================================================

class PassiveIntelSummary(BaseModel):
    """Summary of passive intel for an asset."""
    asset_id: UUID
    asset_value: str
    dns_record_count: int = 0
    certificate_count: int = 0
    historical_url_count: int = 0
    endpoint_count: int = 0
    has_whois: bool = False
    has_asn: bool = False
    has_shodan: bool = False
    security_header_score: Optional[int] = None
    security_header_grade: Optional[str] = None
    favicon_mmh3_hash: Optional[str] = None


class AssetPassiveIntel(BaseModel):
    """Full passive intel data for an asset."""
    asset_id: UUID
    asset_value: str
    dns_records: List[DNSRecord] = []
    whois_record: Optional[WHOISRecord] = None
    certificates: List[Certificate] = []
    asn_info: List[ASNInfo] = []
    historical_urls: List[HistoricalURL] = []
    security_headers: List[SecurityHeader] = []
    favicon_hash: Optional[FaviconHash] = None
    shodan_data: Optional[ShodanData] = None
    crawled_endpoints: List[CrawledEndpoint] = []
