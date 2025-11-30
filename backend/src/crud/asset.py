from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from uuid import UUID
from datetime import datetime, timezone
import logging
from src import models, schemas

logger = logging.getLogger(__name__)

async def create_asset(db: AsyncSession, asset: schemas.AssetCreate, scope_id: UUID):
    # Check if asset exists
    result = await db.execute(
        select(models.Asset)
        .where(models.Asset.scope_id == scope_id)
        .where(models.Asset.value == asset.value)
    )
    db_asset = result.scalar_one_or_none()
    
    if db_asset:
        # Update last_seen
        db_asset.last_seen = datetime.now(timezone.utc)
        db_asset.is_active = True
    else:
        # Create new
        asset_data = asset.model_dump(exclude={"services", "vulnerabilities"})
        db_asset = models.Asset(**asset_data, scope_id=scope_id)
        db.add(db_asset)
        await db.commit()
        await db.refresh(db_asset)
    
    # Handle Services
    for service in asset.services:
        result = await db.execute(
            select(models.Service)
            .where(models.Service.asset_id == db_asset.id)
            .where(models.Service.port == service.port)
            .where(models.Service.protocol == service.protocol)
        )
        db_service = result.scalar_one_or_none()
        if not db_service:
            db_service = models.Service(**service.model_dump(), asset_id=db_asset.id)
            db.add(db_service)
    
    # Handle Vulnerabilities
    new_vulns = []
    logger.info(f"Attempting to create {len(asset.vulnerabilities)} vulnerabilities for asset {asset.value}")
    
    for vuln in asset.vulnerabilities:
            result = await db.execute(
                select(models.Vulnerability)
                .where(models.Vulnerability.asset_id == db_asset.id)
                .where(models.Vulnerability.title == vuln.title)
            )
            db_vuln = result.scalar_one_or_none()
            if not db_vuln:
                vuln_data = vuln.model_dump()
                db_vuln = models.Vulnerability(**vuln_data, asset_id=db_asset.id)
                db.add(db_vuln)
                new_vulns.append(db_vuln)
                logger.info(f"New vulnerability created: {vuln.title} (Severity: {vuln.severity.value})")
            else:
                logger.debug(f"Vulnerability already exists: {vuln.title}")

    await db.commit()
    await db.refresh(db_asset)
    logger.info(f"Asset {db_asset.value}: {len(new_vulns)} new vulnerabilities successfully added to database")
    return db_asset, new_vulns

async def get_assets(db: AsyncSession, skip: int = 0, limit: int = 100):
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

async def get_assets_by_program(db: AsyncSession, program_id: UUID, skip: int = 0, limit: int = 100):
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

async def get_assets_by_scope(db: AsyncSession, scope_id: UUID, skip: int = 0, limit: int = 100):
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
    result = await db.execute(
        select(models.Asset)
        .where(models.Asset.id == asset_id)
        .options(
            selectinload(models.Asset.services),
            selectinload(models.Asset.vulnerabilities)
        )
    )
    return result.scalar_one_or_none()
