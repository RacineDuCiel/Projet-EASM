from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from src import crud, schemas, models
from src.core.celery_utils import celery_app

class ScanService:
    @staticmethod
    async def create_scan(db: AsyncSession, scan_in: schemas.ScanCreate):
        # 1. Verify Scope exists
        scope = await crud.get_scope(db, scan_in.scope_id)
        if not scope:
            return None

        # 2. Create Scan record in DB
        db_scan = await crud.create_scan(db=db, scan=scan_in)
        
        # 3. Trigger Celery task
        # We pass the scan_id so the worker can update the status
        celery_app.send_task(
            'src.tasks.run_scan', 
            args=[scope.value, str(db_scan.id)], 
            queue='discovery'
        )
        
        return db_scan

    @staticmethod
    async def get_scan(db: AsyncSession, scan_id: UUID):
        return await crud.get_scan(db, scan_id)

    @staticmethod
    async def get_scans(db: AsyncSession, skip: int = 0, limit: int = 100):
        return await crud.get_scans(db, skip=skip, limit=limit)

    @staticmethod
    async def get_scans_by_program(db: AsyncSession, program_id: UUID, skip: int = 0, limit: int = 100):
        return await crud.get_scans_by_program(db, program_id, skip=skip, limit=limit)

    @staticmethod
    async def update_status(db: AsyncSession, scan_id: UUID, status: models.ScanStatus):
        return await crud.update_scan_status(db, scan_id, status)
