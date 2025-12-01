from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from src.models.system_log import SystemLog
from src.schemas.system_log import SystemLogCreate

async def create_system_log(db: AsyncSession, log: SystemLogCreate) -> SystemLog:
    db_log = SystemLog(**log.dict())
    db.add(db_log)
    await db.commit()
    await db.refresh(db_log)
    return db_log

async def get_system_logs(db: AsyncSession, skip: int = 0, limit: int = 100) -> list[SystemLog]:
    result = await db.execute(
        select(SystemLog).order_by(SystemLog.created_at.desc()).offset(skip).limit(limit)
    )
    return result.scalars().all()
