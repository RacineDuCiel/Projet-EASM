from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from uuid import UUID
from datetime import datetime, timezone
from src import models, schemas

async def create_scan(db: AsyncSession, scan: schemas.ScanCreate):
    db_scan = models.Scan(**scan.model_dump())
    db.add(db_scan)
    await db.commit()
    await db.refresh(db_scan)
    return db_scan

async def get_scans(db: AsyncSession, skip: int = 0, limit: int = 100):
    result = await db.execute(select(models.Scan).offset(skip).limit(limit))
    return result.scalars().all()

async def get_scans_by_program(db: AsyncSession, program_id: UUID, skip: int = 0, limit: int = 100):
    result = await db.execute(
        select(models.Scan)
        .join(models.Scope)
        .where(models.Scope.program_id == program_id)
        .offset(skip)
        .limit(limit)
    )
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

async def create_scan_event(db: AsyncSession, event: schemas.ScanEventCreate, scan_id: UUID):
    db_event = models.ScanEvent(**event.model_dump(), scan_id=scan_id)
    db.add(db_event)
    await db.commit()
    await db.refresh(db_event)
    return db_event
