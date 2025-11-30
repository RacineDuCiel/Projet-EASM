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

    @staticmethod
    async def check_scheduled_scans(db: AsyncSession):
        from datetime import datetime, timedelta, timezone
        from src.models.enums import ScanFrequency
        
        programs = await crud.get_scheduled_programs(db)
        triggered_scans = []
        
        for program in programs:
            frequency = program.scan_frequency
            delta = None
            
            if frequency == ScanFrequency.daily:
                delta = timedelta(days=1)
            elif frequency == ScanFrequency.weekly:
                delta = timedelta(weeks=1)
            elif frequency == ScanFrequency.monthly:
                delta = timedelta(days=30)
            else:
                continue
                
            for scope in program.scopes:
                latest_scan = await crud.get_latest_scan_for_scope(db, scope.id)
                
                should_scan = False
                if not latest_scan:
                    should_scan = True
                else:
                    now = datetime.now(timezone.utc)
                    last_scan_time = latest_scan.started_at
                    if last_scan_time.tzinfo is None:
                        last_scan_time = last_scan_time.replace(tzinfo=timezone.utc)
                        
                    if now - last_scan_time > delta:
                        should_scan = True
                
                if should_scan:
                    scan_in = schemas.ScanCreate(
                        scope_id=scope.id,
                        scan_type="passive"
                    )
                    new_scan = await ScanService.create_scan(db, scan_in)
                    if new_scan:
                        triggered_scans.append(new_scan.id)
                        
        return triggered_scans
