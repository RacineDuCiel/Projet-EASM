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
from src.models.enums import ScanStatus, ScanFrequency, ScanDepth


logger = logging.getLogger(__name__)


class ScanService:
    # Scan depth configuration defaults
    FAST_PORTS = "80,443,8080,8443"
    FAST_RATE_LIMIT = 300
    FAST_TIMEOUT = 5
    FAST_RETRIES = 1

    DEEP_PORTS = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8000-8010,8080-8090,8443,9000-9010"
    DEEP_RATE_LIMIT = 100
    DEEP_TIMEOUT = 10
    DEEP_RETRIES = 3

    @staticmethod
    def _build_scan_config(scan_depth: ScanDepth, program: models.Program, scan_id: str, target: str, specific_port: int = None) -> dict:
        """Build scan configuration based on depth and program settings.

        Args:
            scan_depth: Fast or deep scan mode
            program: Program with scan configuration
            scan_id: UUID of the scan
            target: Target domain/IP
            specific_port: If provided, scan only this port (skip discovery)
        """
        if scan_depth == ScanDepth.fast:
            ports = program.custom_ports or ScanService.FAST_PORTS
            rate_limit = program.nuclei_rate_limit or ScanService.FAST_RATE_LIMIT
            timeout = program.nuclei_timeout or ScanService.FAST_TIMEOUT
            retries = ScanService.FAST_RETRIES
            enable_full_vuln_scan = False
        else:  # deep
            ports = program.custom_ports or ScanService.DEEP_PORTS
            rate_limit = program.nuclei_rate_limit or ScanService.DEEP_RATE_LIMIT
            timeout = program.nuclei_timeout or ScanService.DEEP_TIMEOUT
            retries = ScanService.DEEP_RETRIES
            enable_full_vuln_scan = True

        # If a specific port is provided, use it instead of port discovery
        if specific_port:
            ports = str(specific_port)

        return {
            "scan_id": scan_id,
            "target": target,
            "scan_depth": scan_depth.value,
            "ports": ports,
            "specific_port": specific_port,  # Pass to workers to skip discovery
            "nuclei_rate_limit": rate_limit,
            "nuclei_timeout": timeout,
            "nuclei_retries": retries,
            "enable_full_vuln_scan": enable_full_vuln_scan
        }

    @staticmethod
    async def create_scan(db: AsyncSession, scan_in: schemas.ScanCreate):
        # 1. Verify Scope exists
        scope = await crud.get_scope(db, scan_in.scope_id)
        if not scope:
            return None

        # 2. Get Program to access scan configuration
        program = await crud.get_program(db, scope.program_id)
        if not program:
            return None

        # 3. Create Scan record in DB
        db_scan = await crud.create_scan(db=db, scan=scan_in)

        # 4. Build scan configuration (pass specific port if defined in scope)
        scan_config = ScanService._build_scan_config(
            scan_in.scan_depth,
            program,
            str(db_scan.id),
            scope.value,
            specific_port=scope.port  # May be None for domains
        )

        # 5. Trigger Celery task with configuration
        celery_app.send_task(
            'src.tasks.run_scan',
            args=[scope.value, str(db_scan.id)],
            kwargs={'scan_config': scan_config},
            queue='discovery'
        )

        logger.info(f"Created scan {db_scan.id} with depth={scan_in.scan_depth.value}")
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
                        scan_type="passive",
                        scan_depth=program.scan_depth  # Use program's configured scan depth
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
        from sqlalchemy.orm import selectinload

        # Find all running scans with scope and program loaded
        result = await db.execute(
            select(Scan)
            .where(Scan.status == ScanStatus.running)
            .options(selectinload(Scan.scope))
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

            if scan.scope:
                # Get program for scan config
                program = await crud.get_program(db, scan.scope.program_id)
                if program:
                    # Build scan configuration
                    scan_config = ScanService._build_scan_config(
                        scan.scan_depth,
                        program,
                        str(scan.id),
                        scan.scope.value,
                        specific_port=scan.scope.port
                    )

                    celery_app.send_task(
                        'src.tasks.run_scan',
                        args=[scan.scope.value, str(scan.id)],
                        kwargs={'scan_config': scan_config},
                        queue='discovery'
                    )
                    count += 1
                    logger.info(f"Resumed scan {scan.id} for scope {scan.scope.value}")
                else:
                    logger.error(f"Could not resume scan {scan.id}: Program not found.")
                    scan.status = ScanStatus.failed
                    db.add(ScanEvent(scan_id=scan.id, message="Failed to resume: Program not found", severity="error"))
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
