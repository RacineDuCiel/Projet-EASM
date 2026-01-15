from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from sqlalchemy import and_
from uuid import UUID
from datetime import datetime, timezone
from typing import List, Tuple, Set
import logging
from src import models, schemas

logger = logging.getLogger(__name__)


async def create_asset(
    db: AsyncSession, asset: schemas.AssetCreate, scope_id: UUID
) -> Tuple[models.Asset, List[models.Vulnerability]]:
    """
    Create or update an asset with its services and vulnerabilities.
    Uses batch operations to avoid N+1 query anti-patterns.
    
    Returns:
        Tuple of (asset, new_vulnerabilities)
    """
    # 1. Check if asset exists
    result = await db.execute(
        select(models.Asset)
        .where(and_(models.Asset.scope_id == scope_id, models.Asset.value == asset.value))
    )
    db_asset = result.scalar_one_or_none()
    
    if db_asset:
        # Update last_seen
        db_asset.last_seen = datetime.now(timezone.utc)
        db_asset.is_active = True
    else:
        # Create new asset
        asset_data = asset.model_dump(exclude={"services", "vulnerabilities"})
        db_asset = models.Asset(**asset_data, scope_id=scope_id)
        db.add(db_asset)
        await db.flush()  # Get the ID without committing
    
    # 2. Batch process Services (O(1) query instead of O(n))
    if asset.services:
        await _batch_create_services(db, db_asset.id, asset.services)
    
    # 3. Batch process Vulnerabilities (O(1) query instead of O(n))
    new_vulns = []
    if asset.vulnerabilities:
        new_vulns = await _batch_create_vulnerabilities(db, db_asset.id, asset.vulnerabilities)
    
    await db.commit()
    await db.refresh(db_asset)
    
    if new_vulns:
        logger.info(f"Asset {db_asset.value}: {len(new_vulns)} new vulnerabilities added")
    
    return db_asset, new_vulns


async def _batch_create_services(
    db: AsyncSession, asset_id: UUID, services: List[schemas.ServiceCreate]
) -> None:
    """
    Batch create services, skipping duplicates.
    Uses a single query to fetch existing services.
    """
    if not services:
        return
    
    # Fetch all existing services in ONE query
    result = await db.execute(
        select(models.Service.port, models.Service.protocol)
        .where(models.Service.asset_id == asset_id)
    )
    existing_set: Set[Tuple[int, str]] = {(row.port, row.protocol) for row in result}
    
    # Filter new services
    new_services = [
        models.Service(**s.model_dump(), asset_id=asset_id)
        for s in services
        if (s.port, s.protocol) not in existing_set
    ]
    
    # Batch add
    if new_services:
        db.add_all(new_services)
        logger.debug(f"Added {len(new_services)} new services for asset {asset_id}")


async def _batch_create_vulnerabilities(
    db: AsyncSession, asset_id: UUID, vulnerabilities: List[schemas.VulnerabilityCreate]
) -> List[models.Vulnerability]:
    """
    Batch create vulnerabilities, skipping duplicates.
    Uses a single query to fetch existing vulnerability titles.
    
    Returns:
        List of newly created vulnerability objects
    """
    if not vulnerabilities:
        return []
    
    # Fetch existing vulnerability titles in ONE query
    result = await db.execute(
        select(models.Vulnerability.title)
        .where(models.Vulnerability.asset_id == asset_id)
    )
    existing_titles: Set[str] = {row.title for row in result}
    
    # Filter and create new vulnerabilities
    new_vulns = []
    for vuln in vulnerabilities:
        if vuln.title not in existing_titles:
            existing_titles.add(vuln.title)  # Prevent duplicates within batch
            db_vuln = models.Vulnerability(**vuln.model_dump(), asset_id=asset_id)
            db.add(db_vuln)
            new_vulns.append(db_vuln)
            logger.info(f"New vulnerability: {vuln.title} (Severity: {vuln.severity.value})")
    
    return new_vulns


async def get_assets(db: AsyncSession, skip: int = 0, limit: int = 100):
    """Get all assets with eager-loaded relationships."""
    result = await db.execute(
        select(models.Asset)
        .options(
            selectinload(models.Asset.services),
            selectinload(models.Asset.vulnerabilities)
        )
        .offset(skip)
        .limit(limit)
    )
    return result.scalars().all()


async def get_assets_by_program(
    db: AsyncSession, program_id: UUID, skip: int = 0, limit: int = 100
):
    """Get assets by program with eager-loaded relationships."""
    result = await db.execute(
        select(models.Asset)
        .join(models.Scope)
        .where(models.Scope.program_id == program_id)
        .options(
            selectinload(models.Asset.services),
            selectinload(models.Asset.vulnerabilities)
        )
        .offset(skip)
        .limit(limit)
    )
    return result.scalars().all()


async def get_assets_by_scope(
    db: AsyncSession, scope_id: UUID, skip: int = 0, limit: int = 100
):
    """Get assets by scope with eager-loaded relationships."""
    result = await db.execute(
        select(models.Asset)
        .where(models.Asset.scope_id == scope_id)
        .options(
            selectinload(models.Asset.services),
            selectinload(models.Asset.vulnerabilities)
        )
        .offset(skip)
        .limit(limit)
    )
    return result.scalars().all()


async def get_asset(db: AsyncSession, asset_id: UUID):
    """Get a single asset by ID with eager-loaded relationships."""
    result = await db.execute(
        select(models.Asset)
        .where(models.Asset.id == asset_id)
        .options(
            selectinload(models.Asset.services),
            selectinload(models.Asset.vulnerabilities)
        )
    )
    return result.scalar_one_or_none()


async def get_asset_by_value(db: AsyncSession, value: str, scope_id: UUID):
    """Get an asset by its value and scope."""
    result = await db.execute(
        select(models.Asset)
        .where(and_(models.Asset.value == value, models.Asset.scope_id == scope_id))
        .options(
            selectinload(models.Asset.services),
            selectinload(models.Asset.vulnerabilities)
        )
    )
    return result.scalar_one_or_none()


async def get_or_create_service(
    db: AsyncSession, asset_id: UUID, port: int, service_name: str = "unknown"
) -> models.Service:
    """Get or create a service for an asset."""
    result = await db.execute(
        select(models.Service)
        .where(and_(
            models.Service.asset_id == asset_id,
            models.Service.port == port,
            models.Service.protocol == "tcp"
        ))
    )
    db_service = result.scalar_one_or_none()
    
    if not db_service:
        db_service = models.Service(
            asset_id=asset_id,
            port=port,
            protocol="tcp",
            service_name=service_name
        )
        db.add(db_service)
        await db.flush()
        logger.info(f"Created service on port {port} for asset {asset_id}")
    
    return db_service


async def get_vulnerability_by_title(
    db: AsyncSession, asset_id: UUID, title: str
) -> models.Vulnerability:
    """Get a vulnerability by asset and title."""
    result = await db.execute(
        select(models.Vulnerability)
        .where(and_(
            models.Vulnerability.asset_id == asset_id,
            models.Vulnerability.title == title
        ))
    )
    return result.scalar_one_or_none()


async def update_service_technologies(
    db: AsyncSession,
    scope_id: UUID,
    asset_value: str,
    port: int,
    technologies: List[str],
    web_server: str = None,
    waf_detected: str = None,
    tls_version: str = None,
    response_time_ms: int = None
) -> models.Service:
    """
    Update a service with technology detection results.
    Creates asset and service if they don't exist.
    """
    import json

    # 1. Get or create asset
    result = await db.execute(
        select(models.Asset)
        .where(and_(
            models.Asset.scope_id == scope_id,
            models.Asset.value == asset_value
        ))
    )
    db_asset = result.scalar_one_or_none()

    if not db_asset:
        # Create new asset
        db_asset = models.Asset(
            scope_id=scope_id,
            value=asset_value,
            asset_type=models.AssetType.subdomain,
            is_active=True
        )
        db.add(db_asset)
        await db.flush()
        logger.info(f"Created asset {asset_value} for tech detection")

    # 2. Get or create service
    result = await db.execute(
        select(models.Service)
        .where(and_(
            models.Service.asset_id == db_asset.id,
            models.Service.port == port,
            models.Service.protocol == "tcp"
        ))
    )
    db_service = result.scalar_one_or_none()

    if not db_service:
        db_service = models.Service(
            asset_id=db_asset.id,
            port=port,
            protocol="tcp",
            service_name="unknown"
        )
        db.add(db_service)
        await db.flush()
        logger.info(f"Created service on port {port} for asset {asset_value}")

    # 3. Update technology fields
    if technologies:
        db_service.technologies = json.dumps(technologies)
    if web_server:
        db_service.web_server = web_server
    if waf_detected:
        db_service.waf_detected = waf_detected
    if tls_version:
        db_service.tls_version = tls_version
    if response_time_ms:
        db_service.response_time_ms = response_time_ms

    await db.commit()
    await db.refresh(db_service)

    logger.info(f"Updated tech detection for {asset_value}:{port} - {len(technologies)} technologies")
    return db_service


async def update_asset(
    db: AsyncSession, asset_id: UUID, asset_update: schemas.AssetUpdate
) -> models.Asset:
    """Update asset properties including criticality."""
    result = await db.execute(
        select(models.Asset)
        .where(models.Asset.id == asset_id)
        .options(
            selectinload(models.Asset.services),
            selectinload(models.Asset.vulnerabilities)
        )
    )
    db_asset = result.scalar_one_or_none()

    if not db_asset:
        return None

    # Update fields if provided
    update_data = asset_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        if value is not None:
            setattr(db_asset, field, value)

    await db.commit()
    await db.refresh(db_asset)

    logger.info(f"Updated asset {db_asset.value} with {update_data}")
    return db_asset
