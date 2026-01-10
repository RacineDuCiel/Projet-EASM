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

async def update_scan_status(
    db: AsyncSession, 
    scan_id: UUID, 
    status: models.ScanStatus
) -> models.Scan | None:
    """
    Update scan status using a single UPDATE query.
    
    Optimized to avoid the SELECT + UPDATE anti-pattern.
    Sets completed_at timestamp for terminal states.
    """
    from sqlalchemy import update
    
    values: dict = {"status": status}
    
    # Set completed_at for terminal states
    terminal_states = [
        models.ScanStatus.completed, 
        models.ScanStatus.failed,
        models.ScanStatus.stopped
    ]
    if status in terminal_states:
        values["completed_at"] = datetime.now(timezone.utc)
    
    # Execute single UPDATE query
    await db.execute(
        update(models.Scan)
        .where(models.Scan.id == scan_id)
        .values(**values)
    )
    await db.commit()
    
    # Fetch and return updated scan
    return await get_scan(db, scan_id)

async def create_scan_event(db: AsyncSession, event: schemas.ScanEventCreate, scan_id: UUID):
    db_event = models.ScanEvent(**event.model_dump(), scan_id=scan_id)
    db.add(db_event)
    await db.commit()
    await db.refresh(db_event)
    return db_event

async def get_latest_scan_for_scope(db: AsyncSession, scope_id: UUID):
    result = await db.execute(
        select(models.Scan)
        .where(models.Scan.scope_id == scope_id)
        .order_by(models.Scan.started_at.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()
