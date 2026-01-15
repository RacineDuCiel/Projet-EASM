"""
Passive Intelligence Models for EASM.
Stores data from passive reconnaissance sources (DNS, WHOIS, certificates, etc.)
"""
import uuid
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Integer, Text, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from src.db.session import Base


class DNSRecord(Base):
    """
    Stores DNS records (A, AAAA, MX, TXT, NS, SOA, CNAME, PTR) for an asset.
    """
    __tablename__ = "dns_records"
    __table_args__ = (
        Index('ix_dns_records_asset_id', 'asset_id'),
        Index('ix_dns_records_type', 'record_type'),
        Index('ix_dns_records_asset_type', 'asset_id', 'record_type'),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    record_type = Column(String(10), nullable=False)  # A, AAAA, MX, TXT, NS, SOA, CNAME, PTR
    record_value = Column(Text, nullable=False)
    ttl = Column(Integer, nullable=True)
    priority = Column(Integer, nullable=True)  # For MX records
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    asset = relationship("Asset", back_populates="dns_records", lazy="selectin")


class WHOISRecord(Base):
    """
    Stores WHOIS data for domains - registrar, creation/expiration dates, name servers.
    """
    __tablename__ = "whois_records"
    __table_args__ = (
        Index('ix_whois_records_asset_id', 'asset_id'),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, unique=True)
    registrar = Column(String(255), nullable=True)
    creation_date = Column(DateTime(timezone=True), nullable=True)
    expiration_date = Column(DateTime(timezone=True), nullable=True)
    updated_date = Column(DateTime(timezone=True), nullable=True)
    name_servers = Column(Text, nullable=True)  # JSON array
    registrant_org = Column(String(255), nullable=True)
    registrant_country = Column(String(10), nullable=True)
    registrant_email = Column(String(255), nullable=True)
    dnssec = Column(Boolean, nullable=True)
    raw_data = Column(Text, nullable=True)  # Full WHOIS response
    collected_at = Column(DateTime(timezone=True), server_default=func.now())

    asset = relationship("Asset", back_populates="whois_record", lazy="selectin")


class Certificate(Base):
    """
    Stores SSL/TLS certificate information from CT logs, tlsx, or API sources.
    """
    __tablename__ = "certificates"
    __table_args__ = (
        Index('ix_certificates_asset_id', 'asset_id'),
        Index('ix_certificates_fingerprint', 'fingerprint_sha256'),
        Index('ix_certificates_expiry', 'not_after'),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    service_id = Column(UUID(as_uuid=True), ForeignKey("services.id", ondelete="SET NULL"), nullable=True)
    serial_number = Column(String(255), nullable=True)
    issuer_cn = Column(String(255), nullable=True)
    issuer_org = Column(String(255), nullable=True)
    subject_cn = Column(String(255), nullable=True)
    subject_alt_names = Column(Text, nullable=True)  # JSON array
    not_before = Column(DateTime(timezone=True), nullable=True)
    not_after = Column(DateTime(timezone=True), nullable=True)
    signature_algorithm = Column(String(100), nullable=True)
    key_algorithm = Column(String(50), nullable=True)
    key_size = Column(Integer, nullable=True)
    is_self_signed = Column(Boolean, nullable=True)
    is_expired = Column(Boolean, nullable=True)
    is_wildcard = Column(Boolean, nullable=True)
    fingerprint_sha256 = Column(String(64), nullable=True)
    tls_version = Column(String(20), nullable=True)
    source = Column(String(50), nullable=True)  # "crt.sh", "tlsx", "censys"
    collected_at = Column(DateTime(timezone=True), server_default=func.now())

    asset = relationship("Asset", back_populates="certificates", lazy="selectin")
    service = relationship("Service", lazy="selectin")


class ASNInfo(Base):
    """
    Stores ASN (Autonomous System Number) information for IP addresses.
    """
    __tablename__ = "asn_info"
    __table_args__ = (
        Index('ix_asn_info_asset_id', 'asset_id'),
        Index('ix_asn_info_asn_number', 'asn_number'),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    ip_address = Column(String(45), nullable=False)  # IPv4 or IPv6
    asn_number = Column(Integer, nullable=True)
    asn_name = Column(String(255), nullable=True)
    asn_description = Column(Text, nullable=True)
    asn_country = Column(String(10), nullable=True)
    bgp_prefix = Column(String(50), nullable=True)
    rir = Column(String(20), nullable=True)  # ARIN, RIPE, APNIC, LACNIC, AFRINIC
    collected_at = Column(DateTime(timezone=True), server_default=func.now())

    asset = relationship("Asset", back_populates="asn_info", lazy="selectin")


class HistoricalURL(Base):
    """
    Stores historical URLs from Web Archive, GAU, CommonCrawl, etc.
    """
    __tablename__ = "historical_urls"
    __table_args__ = (
        Index('ix_historical_urls_asset_id', 'asset_id'),
        Index('ix_historical_urls_source', 'source'),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    url = Column(Text, nullable=False)
    source = Column(String(50), nullable=True)  # "wayback", "gau", "commoncrawl", "alienvault"
    archived_date = Column(DateTime(timezone=True), nullable=True)
    status_code = Column(Integer, nullable=True)
    content_type = Column(String(100), nullable=True)
    collected_at = Column(DateTime(timezone=True), server_default=func.now())

    asset = relationship("Asset", back_populates="historical_urls", lazy="selectin")


class SecurityHeader(Base):
    """
    Stores security headers analysis for web assets.
    """
    __tablename__ = "security_headers"
    __table_args__ = (
        Index('ix_security_headers_asset_id', 'asset_id'),
        Index('ix_security_headers_score', 'score'),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    service_id = Column(UUID(as_uuid=True), ForeignKey("services.id", ondelete="SET NULL"), nullable=True)
    url = Column(String(500), nullable=True)
    # Individual headers
    content_security_policy = Column(Text, nullable=True)
    strict_transport_security = Column(Text, nullable=True)
    x_frame_options = Column(String(50), nullable=True)
    x_content_type_options = Column(String(50), nullable=True)
    x_xss_protection = Column(String(50), nullable=True)
    referrer_policy = Column(String(100), nullable=True)
    permissions_policy = Column(Text, nullable=True)
    # Analysis results
    missing_headers = Column(Text, nullable=True)  # JSON array
    score = Column(Integer, nullable=True)  # 0-100 security score
    grade = Column(String(5), nullable=True)  # A+, A, B, C, D, F
    collected_at = Column(DateTime(timezone=True), server_default=func.now())

    asset = relationship("Asset", back_populates="security_headers", lazy="selectin")
    service = relationship("Service", lazy="selectin")


class FaviconHash(Base):
    """
    Stores favicon hash for fingerprinting (useful for Shodan searches).
    """
    __tablename__ = "favicon_hashes"
    __table_args__ = (
        Index('ix_favicon_hashes_asset_id', 'asset_id'),
        Index('ix_favicon_hashes_mmh3', 'mmh3_hash'),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, unique=True)
    mmh3_hash = Column(String(20), nullable=True)  # MurmurHash3 (Shodan format)
    md5_hash = Column(String(32), nullable=True)
    sha256_hash = Column(String(64), nullable=True)
    favicon_url = Column(Text, nullable=True)
    favicon_size = Column(Integer, nullable=True)  # Bytes
    collected_at = Column(DateTime(timezone=True), server_default=func.now())

    asset = relationship("Asset", back_populates="favicon_hash", lazy="selectin")


class ShodanData(Base):
    """
    Stores Shodan API results for IP addresses.
    """
    __tablename__ = "shodan_data"
    __table_args__ = (
        Index('ix_shodan_data_asset_id', 'asset_id'),
        Index('ix_shodan_data_ip', 'ip_address'),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, unique=True)
    ip_address = Column(String(45), nullable=False)
    open_ports = Column(Text, nullable=True)  # JSON array
    hostnames = Column(Text, nullable=True)  # JSON array
    domains = Column(Text, nullable=True)  # JSON array
    os = Column(String(100), nullable=True)
    isp = Column(String(255), nullable=True)
    org = Column(String(255), nullable=True)
    city = Column(String(100), nullable=True)
    region = Column(String(100), nullable=True)
    country = Column(String(100), nullable=True)
    latitude = Column(String(20), nullable=True)
    longitude = Column(String(20), nullable=True)
    last_update = Column(DateTime(timezone=True), nullable=True)
    vulns = Column(Text, nullable=True)  # JSON array of CVEs
    tags = Column(Text, nullable=True)  # JSON array
    raw_data = Column(Text, nullable=True)  # Full JSON response
    collected_at = Column(DateTime(timezone=True), server_default=func.now())

    asset = relationship("Asset", back_populates="shodan_data", lazy="selectin")


class CrawledEndpoint(Base):
    """
    Stores endpoints discovered by katana crawling or other URL discovery tools.
    """
    __tablename__ = "crawled_endpoints"
    __table_args__ = (
        Index('ix_crawled_endpoints_asset_id', 'asset_id'),
        Index('ix_crawled_endpoints_source', 'source'),
        Index('ix_crawled_endpoints_is_js', 'is_js_file'),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    url = Column(Text, nullable=False)
    method = Column(String(10), default="GET")
    status_code = Column(Integer, nullable=True)
    content_type = Column(String(100), nullable=True)
    content_length = Column(Integer, nullable=True)
    parameters = Column(Text, nullable=True)  # JSON array of params
    source = Column(String(50), nullable=True)  # "katana", "gau", "robots", "sitemap"
    is_js_file = Column(Boolean, default=False)
    is_api_endpoint = Column(Boolean, default=False)
    collected_at = Column(DateTime(timezone=True), server_default=func.now())

    asset = relationship("Asset", back_populates="crawled_endpoints", lazy="selectin")


class TechnologyFingerprint(Base):
    """
    Stores detailed technology fingerprints beyond basic httpx detection.
    """
    __tablename__ = "technology_fingerprints"
    __table_args__ = (
        Index('ix_tech_fingerprints_asset_id', 'asset_id'),
        Index('ix_tech_fingerprints_category', 'category'),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    service_id = Column(UUID(as_uuid=True), ForeignKey("services.id", ondelete="SET NULL"), nullable=True)
    name = Column(String(100), nullable=False)  # e.g., "WordPress"
    version = Column(String(50), nullable=True)  # e.g., "6.4.2"
    category = Column(String(50), nullable=True)  # e.g., "CMS", "Web Server", "Framework"
    confidence = Column(Integer, nullable=True)  # 0-100
    cpe = Column(String(255), nullable=True)  # CPE identifier if available
    detection_method = Column(String(50), nullable=True)  # "header", "body", "script", "meta"
    source = Column(String(50), nullable=True)  # "httpx", "wappalyzer", "nuclei"
    collected_at = Column(DateTime(timezone=True), server_default=func.now())

    asset = relationship("Asset", back_populates="technology_fingerprints", lazy="selectin")
    service = relationship("Service", lazy="selectin")
