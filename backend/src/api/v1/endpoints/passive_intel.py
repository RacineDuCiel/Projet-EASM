"""
API endpoints for Passive Intelligence data.
Receives data from workers and provides read endpoints for frontend.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID
from typing import Dict, Any
import logging

from src.db import session as database
from src.crud import passive_intel as crud
from src.schemas import passive_intel as schemas
from src.services.scan_service import ScanService

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/passive-intel",
    tags=["Passive Intelligence"],
    responses={404: {"description": "Not found"}},
)


# ============================================================================
# Worker Endpoints (POST) - Receive data from Celery workers
# ============================================================================

@router.post("/scans/{scan_id}/dns")
async def receive_dns_records(
    scan_id: UUID,
    payload: schemas.DNSRecordsPayload,
    db: AsyncSession = Depends(database.get_db)
):
    """Receive DNS records from workers."""
    scan = await ScanService.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    records = await crud.create_dns_records(db, scan_id, payload)
    return {"status": "ok", "count": len(records)}


@router.post("/scans/{scan_id}/whois")
async def receive_whois(
    scan_id: UUID,
    payload: schemas.WHOISPayload,
    db: AsyncSession = Depends(database.get_db)
):
    """Receive WHOIS data from workers."""
    scan = await ScanService.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    record = await crud.create_whois_record(db, scan_id, payload)
    return {"status": "ok", "created": record is not None}


@router.post("/scans/{scan_id}/certificates")
async def receive_certificates(
    scan_id: UUID,
    payload: schemas.CertificatesPayload,
    db: AsyncSession = Depends(database.get_db)
):
    """Receive certificates from workers (crt.sh)."""
    scan = await ScanService.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    certs = await crud.create_certificates(db, scan_id, payload)
    return {"status": "ok", "count": len(certs)}


@router.post("/scans/{scan_id}/tls-cert")
async def receive_tls_cert(
    scan_id: UUID,
    payload: schemas.TLSCertPayload,
    db: AsyncSession = Depends(database.get_db)
):
    """Receive TLS certificate from tlsx scan."""
    scan = await ScanService.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    cert = await crud.create_tls_certificate(db, scan_id, payload)
    return {"status": "ok", "created": cert is not None}


@router.post("/scans/{scan_id}/asn")
async def receive_asn(
    scan_id: UUID,
    payload: schemas.ASNPayload,
    db: AsyncSession = Depends(database.get_db)
):
    """Receive ASN information from workers."""
    scan = await ScanService.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    asn = await crud.create_asn_info(db, scan_id, payload)
    return {"status": "ok", "created": asn is not None}


@router.post("/scans/{scan_id}/historical-urls")
async def receive_historical_urls(
    scan_id: UUID,
    payload: schemas.HistoricalURLsPayload,
    db: AsyncSession = Depends(database.get_db)
):
    """Receive historical URLs from workers (wayback, gau)."""
    scan = await ScanService.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    count = await crud.create_historical_urls(db, scan_id, payload)
    return {"status": "ok", "count": count}


@router.post("/scans/{scan_id}/security-headers")
async def receive_security_headers(
    scan_id: UUID,
    payload: schemas.SecurityHeadersPayload,
    db: AsyncSession = Depends(database.get_db)
):
    """Receive security headers analysis from workers."""
    scan = await ScanService.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    headers = await crud.create_security_headers(db, scan_id, payload)
    return {"status": "ok", "created": headers is not None}


@router.post("/scans/{scan_id}/favicon")
async def receive_favicon(
    scan_id: UUID,
    payload: schemas.FaviconPayload,
    db: AsyncSession = Depends(database.get_db)
):
    """Receive favicon hash from workers."""
    scan = await ScanService.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    favicon = await crud.create_favicon_hash(db, scan_id, payload)
    return {"status": "ok", "created": favicon is not None}


@router.post("/scans/{scan_id}/shodan")
async def receive_shodan(
    scan_id: UUID,
    payload: schemas.ShodanPayload,
    db: AsyncSession = Depends(database.get_db)
):
    """Receive Shodan data from workers."""
    scan = await ScanService.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    shodan = await crud.create_shodan_data(db, scan_id, payload)
    return {"status": "ok", "created": shodan is not None}


@router.post("/scans/{scan_id}/endpoints")
async def receive_endpoints(
    scan_id: UUID,
    payload: schemas.EndpointsPayload,
    db: AsyncSession = Depends(database.get_db)
):
    """Receive crawled endpoints from workers (katana)."""
    scan = await ScanService.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    count = await crud.create_crawled_endpoints(db, scan_id, payload)
    return {"status": "ok", "count": count}


@router.post("/scans/{scan_id}/reverse-dns")
async def receive_reverse_dns(
    scan_id: UUID,
    payload: schemas.ReverseDNSPayload,
    db: AsyncSession = Depends(database.get_db)
):
    """Receive reverse DNS (PTR) record from workers."""
    scan = await ScanService.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    record = await crud.create_reverse_dns(db, scan_id, payload)
    return {"status": "ok", "created": record is not None}


# ============================================================================
# Read Endpoints (GET) - For frontend consumption
# ============================================================================

@router.get("/assets/{asset_id}/summary", response_model=schemas.PassiveIntelSummary)
async def get_asset_passive_intel_summary(
    asset_id: UUID,
    db: AsyncSession = Depends(database.get_db)
):
    """Get a summary of passive intel for an asset."""
    # Verify asset exists
    from src.crud.asset import get_asset
    asset = await get_asset(db, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    summary = await crud.get_passive_intel_summary(db, asset_id)
    return schemas.PassiveIntelSummary(
        asset_id=asset_id,
        asset_value=asset.value,
        **summary
    )


@router.get("/assets/{asset_id}", response_model=schemas.AssetPassiveIntel)
async def get_asset_passive_intel(
    asset_id: UUID,
    db: AsyncSession = Depends(database.get_db)
):
    """Get all passive intel data for an asset."""
    from src.crud.asset import get_asset
    asset = await get_asset(db, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    data = await crud.get_full_passive_intel(db, asset_id)
    return schemas.AssetPassiveIntel(
        asset_id=asset_id,
        asset_value=asset.value,
        **data
    )


@router.get("/assets/{asset_id}/dns", response_model=list[schemas.DNSRecord])
async def get_asset_dns_records(
    asset_id: UUID,
    db: AsyncSession = Depends(database.get_db)
):
    """Get DNS records for an asset."""
    records = await crud.get_dns_records(db, asset_id)
    return records


@router.get("/assets/{asset_id}/whois", response_model=schemas.WHOISRecord | None)
async def get_asset_whois(
    asset_id: UUID,
    db: AsyncSession = Depends(database.get_db)
):
    """Get WHOIS record for an asset."""
    record = await crud.get_whois_record(db, asset_id)
    return record


@router.get("/assets/{asset_id}/certificates", response_model=list[schemas.Certificate])
async def get_asset_certificates(
    asset_id: UUID,
    db: AsyncSession = Depends(database.get_db)
):
    """Get certificates for an asset."""
    certs = await crud.get_certificates(db, asset_id)
    return certs


@router.get("/assets/{asset_id}/asn", response_model=list[schemas.ASNInfo])
async def get_asset_asn_info(
    asset_id: UUID,
    db: AsyncSession = Depends(database.get_db)
):
    """Get ASN information for an asset."""
    asn_info = await crud.get_asn_info(db, asset_id)
    return asn_info


@router.get("/assets/{asset_id}/historical-urls", response_model=list[schemas.HistoricalURL])
async def get_asset_historical_urls(
    asset_id: UUID,
    limit: int = 500,
    db: AsyncSession = Depends(database.get_db)
):
    """Get historical URLs for an asset."""
    urls = await crud.get_historical_urls(db, asset_id, limit=limit)
    return urls


@router.get("/assets/{asset_id}/security-headers", response_model=list[schemas.SecurityHeader])
async def get_asset_security_headers(
    asset_id: UUID,
    db: AsyncSession = Depends(database.get_db)
):
    """Get security headers analysis for an asset."""
    headers = await crud.get_security_headers(db, asset_id)
    return headers


@router.get("/assets/{asset_id}/favicon", response_model=schemas.FaviconHash | None)
async def get_asset_favicon(
    asset_id: UUID,
    db: AsyncSession = Depends(database.get_db)
):
    """Get favicon hash for an asset."""
    favicon = await crud.get_favicon_hash(db, asset_id)
    return favicon


@router.get("/assets/{asset_id}/shodan", response_model=schemas.ShodanData | None)
async def get_asset_shodan(
    asset_id: UUID,
    db: AsyncSession = Depends(database.get_db)
):
    """Get Shodan data for an asset."""
    shodan = await crud.get_shodan_data(db, asset_id)
    return shodan


@router.get("/assets/{asset_id}/endpoints", response_model=list[schemas.CrawledEndpoint])
async def get_asset_endpoints(
    asset_id: UUID,
    limit: int = 500,
    db: AsyncSession = Depends(database.get_db)
):
    """Get crawled endpoints for an asset."""
    endpoints = await crud.get_crawled_endpoints(db, asset_id, limit=limit)
    return endpoints
