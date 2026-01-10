"""
Service layer for scan operations.

Handles scan lifecycle management, Celery task orchestration, and scheduled scan triggering.
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src import crud, schemas, models
from src.core.celery_utils import celery_app
from src.models import Scan, ScanEvent
from src.models.enums import ScanStatus, ScanFrequency


logger = logging.getLogger(__name__)


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
    async def check_scheduled_scans(db: AsyncSession) -> List[UUID]:
        """Check and trigger scheduled scans based on program frequency settings."""
        programs = await crud.get_scheduled_programs(db)
        triggered_scans: List[UUID] = []
        
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

    @staticmethod
    async def resume_interrupted_scans(db: AsyncSession) -> int:
        """
        Finds all scans with status 'running' and restarts them.
        This is intended to be run on application startup to handle crashes/restarts.
        """
        # Find all running scans
        result = await db.execute(
            select(Scan).where(Scan.status == ScanStatus.running)
        )
        running_scans = result.scalars().all()
        
        count = 0
        for scan in running_scans:
            # Log the interruption
            event = ScanEvent(
                scan_id=scan.id,
                message="Scan interrupted by system restart. Resuming...",
                severity="info"
            )
            db.add(event)
            
            # Re-queue the task
            # We need to fetch the scope value first
            # Since scope is lazy loaded, we might need to ensure it's available or fetch it
            # In the model definition, scope is lazy="selectin", so it should be there if we awaited the query correctly?
            # Actually result.scalars().all() with async session and selectin load should work.
            # Let's verify if scope is loaded.
            
            if scan.scope:
                 celery_app.send_task(
                    'src.tasks.run_scan', 
                    args=[scan.scope.value, str(scan.id)], 
                    queue='discovery'
                )
                 count += 1
                 logger.info(f"Resumed scan {scan.id} for scope {scan.scope.value}")
            else:
                logger.error(f"Could not resume scan {scan.id}: Scope not found or not loaded.")
                scan.status = ScanStatus.failed
                db.add(ScanEvent(scan_id=scan.id, message="Failed to resume: Scope not found", severity="error"))
            
        if count > 0:
            await db.commit()
            logger.info(f"Resumed {count} interrupted scans.")
        
        return count

    @staticmethod
    async def stop_scan(db: AsyncSession, scan_id: UUID):
        """
        Stops a running scan by revoking its Celery tasks and updating DB status.
        """
        from src.models import Scan, ScanEvent
        from src.models.enums import ScanStatus
        import logging
        
        logger = logging.getLogger(__name__)
        
        scan = await crud.get_scan(db, scan_id)
        if not scan:
            return None
            
        if scan.status not in [ScanStatus.running, ScanStatus.pending]:
            return scan
            
        # 1. Revoke Celery Tasks
        # We need to find active tasks for this scan_id.
        # This is tricky because we don't store the celery task ID in the DB (we could, but we don't right now).
        # However, we can inspect active tasks and match the args.
        
        i = celery_app.control.inspect()
        active = i.active()
        reserved = i.reserved()
        
        tasks_to_revoke = []
        
        def find_tasks(worker_tasks):
            if not worker_tasks: return
            for worker, tasks in worker_tasks.items():
                for task in tasks:
                    # Check args. Our tasks usually have scan_id as the 2nd arg (discovery) or passed in kwargs?
                    # discovery_task(target, scan_id)
                    # run_scan(target, scan_id)
                    # port_scan_task(asset, scan_id)
                    # vuln_scan_task(asset, scan_id)
                    
                    # Args are usually a list.
                    args = task.get('args', [])
                    # kwargs = task.get('kwargs', {})
                    
                    # Check if scan_id is in args
                    if str(scan_id) in [str(arg) for arg in args]:
                        tasks_to_revoke.append(task['id'])
        
        find_tasks(active)
        find_tasks(reserved)
        
        if tasks_to_revoke:
            celery_app.control.revoke(tasks_to_revoke, terminate=True)
            logger.info(f"Revoked {len(tasks_to_revoke)} tasks for scan {scan_id}")
            
        # 2. Update DB
        scan.status = ScanStatus.stopped
        from datetime import datetime, timezone
        scan.completed_at = datetime.now(timezone.utc)
        
        db.add(ScanEvent(
            scan_id=scan.id,
            message="Scan manually stopped by user.",
            severity="warning"
        ))
        
        await db.commit()
        await db.refresh(scan)
        return scan
