from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from uuid import UUID
from datetime import datetime, timezone
from . import models, schemas

async def create_program(db: AsyncSession, program: schemas.ProgramCreate):
    db_program = models.Program(name=program.name)
    db.add(db_program)
    await db.commit()
    await db.refresh(db_program)
    return db_program

async def get_programs(db: AsyncSession, skip: int = 0, limit: int = 100):
    result = await db.execute(select(models.Program).offset(skip).limit(limit))
    return result.scalars().all()

async def get_program(db: AsyncSession, program_id: UUID):
    result = await db.execute(
        select(models.Program)
        .options(selectinload(models.Program.scopes))
        .where(models.Program.id == program_id)
    )
    return result.scalar_one_or_none()

async def create_scope(db: AsyncSession, scope: schemas.ScopeCreate, program_id: UUID):
    db_scope = models.Scope(**scope.model_dump(), program_id=program_id)
    db.add(db_scope)
    await db.commit()
    await db.refresh(db_scope)
    return db_scope

async def get_scopes(db: AsyncSession, program_id: UUID):
    result = await db.execute(select(models.Scope).where(models.Scope.program_id == program_id))
    return result.scalars().all()

async def get_scope(db: AsyncSession, scope_id: UUID):
    result = await db.execute(select(models.Scope).where(models.Scope.id == scope_id))
    return result.scalar_one_or_none()

async def create_scan(db: AsyncSession, scan: schemas.ScanCreate):
    db_scan = models.Scan(**scan.model_dump())
    db.add(db_scan)
    await db.commit()
    await db.refresh(db_scan)
    return db_scan

async def get_scans(db: AsyncSession, skip: int = 0, limit: int = 100):
    result = await db.execute(select(models.Scan).offset(skip).limit(limit))
    return result.scalars().all()

async def get_scan(db: AsyncSession, scan_id: UUID):
    result = await db.execute(select(models.Scan).where(models.Scan.id == scan_id))
    return result.scalar_one_or_none()

async def update_scan_status(db: AsyncSession, scan_id: UUID, status: models.ScanStatus):
    scan = await get_scan(db, scan_id)
    if scan:
        scan.status = status
        if status in [models.ScanStatus.completed, models.ScanStatus.failed]:
            scan.completed_at = datetime.now(timezone.utc)
        await db.commit()
        await db.refresh(scan)
    return scan

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
        db_asset.is_active = True # Re-activate if it was inactive
    else:
        # Create new
        # We need to exclude services/vulns from the Asset model creation
        asset_data = asset.model_dump(exclude={"services", "vulnerabilities"})
        db_asset = models.Asset(**asset_data, scope_id=scope_id)
        db.add(db_asset)
        await db.commit()
        await db.refresh(db_asset)
    
    # Handle Services
    for service in asset.services:
        # Check if service exists (by port/proto)
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
    for vuln in asset.vulnerabilities:
        # Check if vuln exists (by title) - simplified dedup
        result = await db.execute(
            select(models.Vulnerability)
            .where(models.Vulnerability.asset_id == db_asset.id)
            .where(models.Vulnerability.title == vuln.title)
        )
        db_vuln = result.scalar_one_or_none()
        if not db_vuln:
            db_vuln = models.Vulnerability(**vuln.model_dump(), asset_id=db_asset.id)
            db.add(db_vuln)

    await db.commit()
    await db.refresh(db_asset)
    return db_asset

async def get_assets(db: AsyncSession, skip: int = 0, limit: int = 100):
    result = await db.execute(select(models.Asset).offset(skip).limit(limit))
    return result.scalars().all()
