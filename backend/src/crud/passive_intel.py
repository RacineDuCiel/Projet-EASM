"""
CRUD operations for Passive Intelligence data.
Handles database operations for DNS, WHOIS, certificates, ASN, and other passive recon data.
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from sqlalchemy import and_, func
from uuid import UUID
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any, Tuple
import logging
import json

from src import models
from src.schemas import passive_intel as schemas

logger = logging.getLogger(__name__)


# ============================================================================
# Helper Functions
# ============================================================================

async def get_asset_by_value_and_scope(
    db: AsyncSession, asset_value: str, scope_id: UUID
) -> Optional[models.Asset]:
    """Get an asset by its value and scope ID."""
    result = await db.execute(
        select(models.Asset)
        .where(and_(
            models.Asset.value == asset_value,
            models.Asset.scope_id == scope_id
        ))
    )
    return result.scalar_one_or_none()


async def get_asset_by_value_and_scan(
    db: AsyncSession, asset_value: str, scan_id: UUID
) -> Optional[Tuple[models.Asset, UUID]]:
    """
    Get an asset by its value and scan ID.
    Returns the asset and its scope_id.
    """
    # First get the scan to get scope_id
    scan_result = await db.execute(
        select(models.Scan.scope_id)
        .where(models.Scan.id == scan_id)
    )
    scope_id = scan_result.scalar_one_or_none()

    if not scope_id:
        return None

    asset = await get_asset_by_value_and_scope(db, asset_value, scope_id)
    return (asset, scope_id) if asset else None


async def get_or_create_asset_for_scan(
    db: AsyncSession, asset_value: str, scan_id: UUID
) -> Optional[models.Asset]:
    """
    Get or create an asset for a scan.
    If the asset doesn't exist, creates it.
    """
    result = await get_asset_by_value_and_scan(db, asset_value, scan_id)

    if result:
        return result[0]

    # Get scope_id from scan
    scan_result = await db.execute(
        select(models.Scan.scope_id)
        .where(models.Scan.id == scan_id)
    )
    scope_id = scan_result.scalar_one_or_none()

    if not scope_id:
        return None

    # Create new asset
    db_asset = models.Asset(
        scope_id=scope_id,
        value=asset_value,
        asset_type=models.AssetType.subdomain,
        is_active=True
    )
    db.add(db_asset)
    await db.flush()
    logger.info(f"Created asset {asset_value} for passive intel")

    return db_asset


# ============================================================================
# DNS Records
# ============================================================================

async def create_dns_records(
    db: AsyncSession,
    scan_id: UUID,
    payload: schemas.DNSRecordsPayload
) -> List[models.DNSRecord]:
    """Create or update DNS records for an asset."""
    asset = await get_or_create_asset_for_scan(db, payload.asset_value, scan_id)
    if not asset:
        logger.error(f"Could not find/create asset for DNS records: {payload.asset_value}")
        return []

    created_records = []
    now = datetime.now(timezone.utc)

    for record_data in payload.records:
        # Check if record already exists
        result = await db.execute(
            select(models.DNSRecord)
            .where(and_(
                models.DNSRecord.asset_id == asset.id,
                models.DNSRecord.record_type == record_data.record_type,
                models.DNSRecord.record_value == record_data.record_value
            ))
        )
        existing = result.scalar_one_or_none()

        if existing:
            # Update last_seen
            existing.last_seen = now
            existing.ttl = record_data.ttl
            existing.priority = record_data.priority
            created_records.append(existing)
        else:
            # Create new record
            db_record = models.DNSRecord(
                asset_id=asset.id,
                record_type=record_data.record_type,
                record_value=record_data.record_value,
                ttl=record_data.ttl,
                priority=record_data.priority,
                first_seen=now,
                last_seen=now
            )
            db.add(db_record)
            created_records.append(db_record)

    await db.commit()
    logger.info(f"Created/updated {len(created_records)} DNS records for {payload.asset_value}")
    return created_records


async def get_dns_records(
    db: AsyncSession, asset_id: UUID
) -> List[models.DNSRecord]:
    """Get all DNS records for an asset."""
    result = await db.execute(
        select(models.DNSRecord)
        .where(models.DNSRecord.asset_id == asset_id)
        .order_by(models.DNSRecord.record_type)
    )
    return list(result.scalars().all())


# ============================================================================
# WHOIS Records
# ============================================================================

async def create_whois_record(
    db: AsyncSession,
    scan_id: UUID,
    payload: schemas.WHOISPayload
) -> Optional[models.WHOISRecord]:
    """Create or update WHOIS record for an asset."""
    asset = await get_or_create_asset_for_scan(db, payload.asset_value, scan_id)
    if not asset:
        logger.error(f"Could not find/create asset for WHOIS: {payload.asset_value}")
        return None

    # Check if WHOIS record exists
    result = await db.execute(
        select(models.WHOISRecord)
        .where(models.WHOISRecord.asset_id == asset.id)
    )
    existing = result.scalar_one_or_none()

    whois_data = payload.whois_data.model_dump()

    if existing:
        # Update existing record
        for key, value in whois_data.items():
            if value is not None:
                setattr(existing, key, value)
        existing.collected_at = datetime.now(timezone.utc)
        db_record = existing
    else:
        # Create new record
        db_record = models.WHOISRecord(
            asset_id=asset.id,
            **whois_data,
            collected_at=datetime.now(timezone.utc)
        )
        db.add(db_record)

    await db.commit()
    logger.info(f"Created/updated WHOIS record for {payload.asset_value}")
    return db_record


async def get_whois_record(
    db: AsyncSession, asset_id: UUID
) -> Optional[models.WHOISRecord]:
    """Get WHOIS record for an asset."""
    result = await db.execute(
        select(models.WHOISRecord)
        .where(models.WHOISRecord.asset_id == asset_id)
    )
    return result.scalar_one_or_none()


# ============================================================================
# Certificates
# ============================================================================

async def create_certificates(
    db: AsyncSession,
    scan_id: UUID,
    payload: schemas.CertificatesPayload
) -> List[models.Certificate]:
    """Create certificates for an asset."""
    asset = await get_or_create_asset_for_scan(db, payload.asset_value, scan_id)
    if not asset:
        logger.error(f"Could not find/create asset for certificates: {payload.asset_value}")
        return []

    created_certs = []
    now = datetime.now(timezone.utc)

    for cert_data in payload.certificates:
        # Check if certificate already exists (by fingerprint)
        if cert_data.fingerprint_sha256:
            result = await db.execute(
                select(models.Certificate)
                .where(and_(
                    models.Certificate.asset_id == asset.id,
                    models.Certificate.fingerprint_sha256 == cert_data.fingerprint_sha256
                ))
            )
            existing = result.scalar_one_or_none()
            if existing:
                # Update collected_at
                existing.collected_at = now
                created_certs.append(existing)
                continue

        # Create new certificate
        db_cert = models.Certificate(
            asset_id=asset.id,
            **cert_data.model_dump(),
            collected_at=now
        )
        db.add(db_cert)
        created_certs.append(db_cert)

    await db.commit()
    logger.info(f"Created/updated {len(created_certs)} certificates for {payload.asset_value}")
    return created_certs


async def create_tls_certificate(
    db: AsyncSession,
    scan_id: UUID,
    payload: schemas.TLSCertPayload
) -> Optional[models.Certificate]:
    """Create a single TLS certificate from tlsx scan."""
    asset = await get_or_create_asset_for_scan(db, payload.asset_value, scan_id)
    if not asset:
        logger.error(f"Could not find/create asset for TLS cert: {payload.asset_value}")
        return None

    cert_data = payload.certificate
    now = datetime.now(timezone.utc)

    # Check if certificate already exists (by fingerprint)
    if cert_data.fingerprint_sha256:
        result = await db.execute(
            select(models.Certificate)
            .where(and_(
                models.Certificate.asset_id == asset.id,
                models.Certificate.fingerprint_sha256 == cert_data.fingerprint_sha256
            ))
        )
        existing = result.scalar_one_or_none()
        if existing:
            existing.collected_at = now
            await db.commit()
            return existing

    # Create new certificate
    db_cert = models.Certificate(
        asset_id=asset.id,
        **cert_data.model_dump(),
        collected_at=now
    )
    db.add(db_cert)
    await db.commit()
    logger.info(f"Created TLS certificate for {payload.asset_value}")
    return db_cert


async def get_certificates(
    db: AsyncSession, asset_id: UUID
) -> List[models.Certificate]:
    """Get all certificates for an asset."""
    result = await db.execute(
        select(models.Certificate)
        .where(models.Certificate.asset_id == asset_id)
        .order_by(models.Certificate.collected_at.desc())
    )
    return list(result.scalars().all())


# ============================================================================
# ASN Information
# ============================================================================

async def create_asn_info(
    db: AsyncSession,
    scan_id: UUID,
    payload: schemas.ASNPayload
) -> Optional[models.ASNInfo]:
    """Create or update ASN information for an asset."""
    asset = await get_or_create_asset_for_scan(db, payload.asset_value, scan_id)
    if not asset:
        logger.error(f"Could not find/create asset for ASN: {payload.asset_value}")
        return None

    asn_data = payload.asn_data
    now = datetime.now(timezone.utc)

    # Check if ASN record exists for this IP
    result = await db.execute(
        select(models.ASNInfo)
        .where(and_(
            models.ASNInfo.asset_id == asset.id,
            models.ASNInfo.ip_address == asn_data.ip_address
        ))
    )
    existing = result.scalar_one_or_none()

    if existing:
        # Update existing record
        for key, value in asn_data.model_dump().items():
            if value is not None:
                setattr(existing, key, value)
        existing.collected_at = now
        db_record = existing
    else:
        # Create new record
        db_record = models.ASNInfo(
            asset_id=asset.id,
            **asn_data.model_dump(),
            collected_at=now
        )
        db.add(db_record)

    await db.commit()
    logger.info(f"Created/updated ASN info for {payload.asset_value} ({asn_data.ip_address})")
    return db_record


async def get_asn_info(
    db: AsyncSession, asset_id: UUID
) -> List[models.ASNInfo]:
    """Get all ASN information for an asset."""
    result = await db.execute(
        select(models.ASNInfo)
        .where(models.ASNInfo.asset_id == asset_id)
    )
    return list(result.scalars().all())


# ============================================================================
# Historical URLs
# ============================================================================

async def create_historical_urls(
    db: AsyncSession,
    scan_id: UUID,
    payload: schemas.HistoricalURLsPayload
) -> int:
    """Create historical URLs for an asset. Returns count of new URLs."""
    asset = await get_or_create_asset_for_scan(db, payload.asset_value, scan_id)
    if not asset:
        logger.error(f"Could not find/create asset for historical URLs: {payload.asset_value}")
        return 0

    # Get existing URLs for this asset
    result = await db.execute(
        select(models.HistoricalURL.url)
        .where(models.HistoricalURL.asset_id == asset.id)
    )
    existing_urls = {row.url for row in result}

    now = datetime.now(timezone.utc)
    new_count = 0

    for url_data in payload.urls:
        url = url_data.get("url") if isinstance(url_data, dict) else str(url_data)
        if not url or url in existing_urls:
            continue

        db_url = models.HistoricalURL(
            asset_id=asset.id,
            url=url,
            source=payload.source or url_data.get("source") if isinstance(url_data, dict) else payload.source,
            archived_date=url_data.get("archived_date") if isinstance(url_data, dict) else None,
            status_code=url_data.get("status_code") if isinstance(url_data, dict) else None,
            content_type=url_data.get("content_type") if isinstance(url_data, dict) else None,
            collected_at=now
        )
        db.add(db_url)
        existing_urls.add(url)
        new_count += 1

    await db.commit()
    logger.info(f"Created {new_count} historical URLs for {payload.asset_value}")
    return new_count


async def get_historical_urls(
    db: AsyncSession, asset_id: UUID, limit: int = 1000
) -> List[models.HistoricalURL]:
    """Get historical URLs for an asset."""
    result = await db.execute(
        select(models.HistoricalURL)
        .where(models.HistoricalURL.asset_id == asset_id)
        .order_by(models.HistoricalURL.collected_at.desc())
        .limit(limit)
    )
    return list(result.scalars().all())


# ============================================================================
# Security Headers
# ============================================================================

async def create_security_headers(
    db: AsyncSession,
    scan_id: UUID,
    payload: schemas.SecurityHeadersPayload
) -> Optional[models.SecurityHeader]:
    """Create or update security headers for an asset."""
    asset = await get_or_create_asset_for_scan(db, payload.asset_value, scan_id)
    if not asset:
        logger.error(f"Could not find/create asset for security headers: {payload.asset_value}")
        return None

    headers_data = payload.headers.model_dump()
    now = datetime.now(timezone.utc)

    # Check if record exists for this URL
    url = headers_data.get("url", payload.asset_value)
    result = await db.execute(
        select(models.SecurityHeader)
        .where(and_(
            models.SecurityHeader.asset_id == asset.id,
            models.SecurityHeader.url == url
        ))
    )
    existing = result.scalar_one_or_none()

    if existing:
        # Update existing record
        for key, value in headers_data.items():
            if value is not None:
                setattr(existing, key, value)
        existing.collected_at = now
        db_record = existing
    else:
        # Create new record
        db_record = models.SecurityHeader(
            asset_id=asset.id,
            **headers_data,
            collected_at=now
        )
        db.add(db_record)

    await db.commit()
    logger.info(f"Created/updated security headers for {payload.asset_value} (grade: {headers_data.get('grade')})")
    return db_record


async def get_security_headers(
    db: AsyncSession, asset_id: UUID
) -> List[models.SecurityHeader]:
    """Get security headers for an asset."""
    result = await db.execute(
        select(models.SecurityHeader)
        .where(models.SecurityHeader.asset_id == asset_id)
        .order_by(models.SecurityHeader.collected_at.desc())
    )
    return list(result.scalars().all())


# ============================================================================
# Favicon Hash
# ============================================================================

async def create_favicon_hash(
    db: AsyncSession,
    scan_id: UUID,
    payload: schemas.FaviconPayload
) -> Optional[models.FaviconHash]:
    """Create or update favicon hash for an asset."""
    asset = await get_or_create_asset_for_scan(db, payload.asset_value, scan_id)
    if not asset:
        logger.error(f"Could not find/create asset for favicon: {payload.asset_value}")
        return None

    favicon_data = payload.favicon_hash.model_dump()
    now = datetime.now(timezone.utc)

    # Check if favicon record exists
    result = await db.execute(
        select(models.FaviconHash)
        .where(models.FaviconHash.asset_id == asset.id)
    )
    existing = result.scalar_one_or_none()

    if existing:
        # Update existing record
        for key, value in favicon_data.items():
            if value is not None:
                setattr(existing, key, value)
        existing.collected_at = now
        db_record = existing
    else:
        # Create new record
        db_record = models.FaviconHash(
            asset_id=asset.id,
            **favicon_data,
            collected_at=now
        )
        db.add(db_record)

    await db.commit()
    logger.info(f"Created/updated favicon hash for {payload.asset_value}")
    return db_record


async def get_favicon_hash(
    db: AsyncSession, asset_id: UUID
) -> Optional[models.FaviconHash]:
    """Get favicon hash for an asset."""
    result = await db.execute(
        select(models.FaviconHash)
        .where(models.FaviconHash.asset_id == asset_id)
    )
    return result.scalar_one_or_none()


# ============================================================================
# Shodan Data
# ============================================================================

async def create_shodan_data(
    db: AsyncSession,
    scan_id: UUID,
    payload: schemas.ShodanPayload
) -> Optional[models.ShodanData]:
    """Create or update Shodan data for an asset."""
    asset = await get_or_create_asset_for_scan(db, payload.asset_value, scan_id)
    if not asset:
        logger.error(f"Could not find/create asset for Shodan: {payload.asset_value}")
        return None

    shodan_data = payload.shodan_data.model_dump()
    now = datetime.now(timezone.utc)

    # Check if Shodan record exists for this IP
    ip_address = shodan_data.get("ip_address")
    result = await db.execute(
        select(models.ShodanData)
        .where(and_(
            models.ShodanData.asset_id == asset.id,
            models.ShodanData.ip_address == ip_address
        ))
    )
    existing = result.scalar_one_or_none()

    if existing:
        # Update existing record
        for key, value in shodan_data.items():
            if value is not None:
                setattr(existing, key, value)
        existing.collected_at = now
        db_record = existing
    else:
        # Create new record
        db_record = models.ShodanData(
            asset_id=asset.id,
            **shodan_data,
            collected_at=now
        )
        db.add(db_record)

    await db.commit()
    logger.info(f"Created/updated Shodan data for {payload.asset_value} ({ip_address})")
    return db_record


async def get_shodan_data(
    db: AsyncSession, asset_id: UUID
) -> Optional[models.ShodanData]:
    """Get Shodan data for an asset."""
    result = await db.execute(
        select(models.ShodanData)
        .where(models.ShodanData.asset_id == asset_id)
    )
    return result.scalar_one_or_none()


# ============================================================================
# Crawled Endpoints
# ============================================================================

async def create_crawled_endpoints(
    db: AsyncSession,
    scan_id: UUID,
    payload: schemas.EndpointsPayload
) -> int:
    """Create crawled endpoints for an asset. Returns count of new endpoints."""
    asset = await get_or_create_asset_for_scan(db, payload.asset_value, scan_id)
    if not asset:
        logger.error(f"Could not find/create asset for endpoints: {payload.asset_value}")
        return 0

    # Get existing URLs for this asset
    result = await db.execute(
        select(models.CrawledEndpoint.url)
        .where(models.CrawledEndpoint.asset_id == asset.id)
    )
    existing_urls = {row.url for row in result}

    now = datetime.now(timezone.utc)
    new_count = 0

    for endpoint_data in payload.endpoints:
        url = endpoint_data.get("url")
        if not url or url in existing_urls:
            continue

        db_endpoint = models.CrawledEndpoint(
            asset_id=asset.id,
            url=url,
            method=endpoint_data.get("method", "GET"),
            status_code=endpoint_data.get("status_code"),
            content_type=endpoint_data.get("content_type"),
            content_length=endpoint_data.get("content_length"),
            parameters=json.dumps(endpoint_data.get("parameters")) if endpoint_data.get("parameters") else None,
            source=endpoint_data.get("source"),
            is_js_file=endpoint_data.get("is_js_file", False),
            is_api_endpoint=endpoint_data.get("is_api_endpoint", False),
            collected_at=now
        )
        db.add(db_endpoint)
        existing_urls.add(url)
        new_count += 1

    await db.commit()
    logger.info(f"Created {new_count} crawled endpoints for {payload.asset_value}")
    return new_count


async def get_crawled_endpoints(
    db: AsyncSession, asset_id: UUID, limit: int = 1000
) -> List[models.CrawledEndpoint]:
    """Get crawled endpoints for an asset."""
    result = await db.execute(
        select(models.CrawledEndpoint)
        .where(models.CrawledEndpoint.asset_id == asset_id)
        .order_by(models.CrawledEndpoint.collected_at.desc())
        .limit(limit)
    )
    return list(result.scalars().all())


# ============================================================================
# Reverse DNS
# ============================================================================

async def create_reverse_dns(
    db: AsyncSession,
    scan_id: UUID,
    payload: schemas.ReverseDNSPayload
) -> Optional[models.DNSRecord]:
    """Create a reverse DNS (PTR) record for an asset."""
    if not payload.ptr_hostname:
        return None

    asset = await get_or_create_asset_for_scan(db, payload.asset_value, scan_id)
    if not asset:
        logger.error(f"Could not find/create asset for reverse DNS: {payload.asset_value}")
        return None

    now = datetime.now(timezone.utc)

    # Check if PTR record already exists
    result = await db.execute(
        select(models.DNSRecord)
        .where(and_(
            models.DNSRecord.asset_id == asset.id,
            models.DNSRecord.record_type == "PTR",
            models.DNSRecord.record_value == payload.ptr_hostname
        ))
    )
    existing = result.scalar_one_or_none()

    if existing:
        existing.last_seen = now
        await db.commit()
        return existing

    # Create new PTR record
    db_record = models.DNSRecord(
        asset_id=asset.id,
        record_type="PTR",
        record_value=payload.ptr_hostname,
        first_seen=now,
        last_seen=now
    )
    db.add(db_record)
    await db.commit()
    logger.info(f"Created PTR record for {payload.asset_value}: {payload.ptr_hostname}")
    return db_record


# ============================================================================
# Summary / Aggregated Views
# ============================================================================

async def get_passive_intel_summary(
    db: AsyncSession, asset_id: UUID
) -> Dict[str, Any]:
    """Get a summary of passive intel for an asset."""
    # Get counts using aggregation queries
    dns_count = await db.scalar(
        select(func.count()).where(models.DNSRecord.asset_id == asset_id)
    )
    cert_count = await db.scalar(
        select(func.count()).where(models.Certificate.asset_id == asset_id)
    )
    url_count = await db.scalar(
        select(func.count()).where(models.HistoricalURL.asset_id == asset_id)
    )
    endpoint_count = await db.scalar(
        select(func.count()).where(models.CrawledEndpoint.asset_id == asset_id)
    )

    # Check for existence of single records
    has_whois = await db.scalar(
        select(func.count()).where(models.WHOISRecord.asset_id == asset_id)
    ) > 0
    has_asn = await db.scalar(
        select(func.count()).where(models.ASNInfo.asset_id == asset_id)
    ) > 0
    has_shodan = await db.scalar(
        select(func.count()).where(models.ShodanData.asset_id == asset_id)
    ) > 0

    # Get security header grade (latest)
    sec_headers = await db.execute(
        select(models.SecurityHeader.score, models.SecurityHeader.grade)
        .where(models.SecurityHeader.asset_id == asset_id)
        .order_by(models.SecurityHeader.collected_at.desc())
        .limit(1)
    )
    sec_header_row = sec_headers.first()

    # Get favicon hash
    favicon = await db.execute(
        select(models.FaviconHash.mmh3_hash)
        .where(models.FaviconHash.asset_id == asset_id)
    )
    favicon_row = favicon.first()

    return {
        "dns_record_count": dns_count or 0,
        "certificate_count": cert_count or 0,
        "historical_url_count": url_count or 0,
        "endpoint_count": endpoint_count or 0,
        "has_whois": has_whois,
        "has_asn": has_asn,
        "has_shodan": has_shodan,
        "security_header_score": sec_header_row.score if sec_header_row else None,
        "security_header_grade": sec_header_row.grade if sec_header_row else None,
        "favicon_mmh3_hash": favicon_row.mmh3_hash if favicon_row else None
    }


async def get_full_passive_intel(
    db: AsyncSession, asset_id: UUID
) -> Dict[str, Any]:
    """Get all passive intel data for an asset."""
    # Fetch all data in parallel-ish manner
    dns_records = await get_dns_records(db, asset_id)
    whois_record = await get_whois_record(db, asset_id)
    certificates = await get_certificates(db, asset_id)
    asn_info = await get_asn_info(db, asset_id)
    historical_urls = await get_historical_urls(db, asset_id, limit=500)
    security_headers = await get_security_headers(db, asset_id)
    favicon_hash = await get_favicon_hash(db, asset_id)
    shodan_data = await get_shodan_data(db, asset_id)
    crawled_endpoints = await get_crawled_endpoints(db, asset_id, limit=500)

    return {
        "dns_records": dns_records,
        "whois_record": whois_record,
        "certificates": certificates,
        "asn_info": asn_info,
        "historical_urls": historical_urls,
        "security_headers": security_headers,
        "favicon_hash": favicon_hash,
        "shodan_data": shodan_data,
        "crawled_endpoints": crawled_endpoints
    }
