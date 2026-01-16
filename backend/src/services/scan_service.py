"""
Service layer for scan operations.

Handles scan lifecycle management, Celery task orchestration, and scheduled scan triggering.
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src import crud, schemas, models
from src.core.celery_utils import celery_app
from src.models import Scan, ScanEvent
from src.models.enums import ScanStatus, ScanFrequency, ScanProfile
from src.services.profile_config import build_profile_config, get_all_profiles_info


logger = logging.getLogger(__name__)


class ScanService:

    @staticmethod
    def _build_scan_config(
        profile: ScanProfile,
        program: models.Program,
        scan_id: str,
        target: str,
        specific_port: int = None,
        force_delta: bool = False
    ) -> Dict[str, Any]:
        """Build scan configuration based on profile and program settings.

        Args:
            profile: Scan profile to use
            program: Program with scan configuration overrides
            scan_id: UUID of the scan
            target: Target domain/IP
            specific_port: If provided, scan only this port (skip discovery)
            force_delta: If True, enable delta scanning mode regardless of profile
        """
        # Get program overrides
        program_overrides = {
            "custom_ports": program.custom_ports,
            "nuclei_rate_limit": program.nuclei_rate_limit,
            "nuclei_timeout": program.nuclei_timeout,
        }

        # Build profile config with program overrides
        config = build_profile_config(profile, program_overrides)

        # If a specific port is provided, use it instead of port discovery
        ports = str(specific_port) if specific_port else config.ports

        # Delta mode: from profile config OR forced by scheduled scan
        is_delta = config.is_delta_scan or force_delta
        delta_hours = program.delta_scan_threshold_hours if is_delta else None

        return {
            "scan_id": scan_id,
            "target": target,
            "scan_profile": profile.value,
            "phases": [p.value for p in config.phases],
            "ports": ports,
            "specific_port": specific_port,
            "nuclei_rate_limit": config.nuclei_rate_limit,
            "nuclei_timeout": config.nuclei_timeout,
            "nuclei_retries": config.nuclei_retries,
            "run_prioritized_templates": config.run_prioritized_templates,
            "run_full_templates": config.run_full_templates,
            "passive_recon_enabled": config.passive_recon_enabled,
            "passive_extended_enabled": config.passive_extended_enabled,
            "is_delta_scan": is_delta,
            "delta_threshold_hours": delta_hours,
            "enable_api_integrations": config.enable_api_integrations,
            # API keys from program
            "api_keys": {
                "shodan_key": program.shodan_api_key,
                "securitytrails_key": program.securitytrails_api_key,
                "censys_id": program.censys_api_id,
                "censys_secret": program.censys_api_secret,
            }
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
            scan_in.scan_profile,
            program,
            str(db_scan.id),
            scope.value,
            specific_port=scope.port
        )

        # 5. Trigger Celery task with configuration
        celery_app.send_task(
            'src.tasks.run_scan',
            args=[scope.value, str(db_scan.id)],
            kwargs={'scan_config': scan_config},
            queue='discovery'
        )

        logger.info(f"Created scan {db_scan.id} with profile={scan_in.scan_profile.value}")
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
    def get_available_profiles() -> List[Dict[str, Any]]:
        """Return list of available profiles with their descriptions."""
        return get_all_profiles_info()

    @staticmethod
    async def check_scheduled_scans(db: AsyncSession) -> List[UUID]:
        """Check and trigger scheduled scans based on program monitoring settings.

        Scheduled scans always use full_audit profile (maximum intensity).
        Delta mode can be enabled per-program to only scan stale assets.
        """
        programs = await crud.get_scheduled_programs(db)
        triggered_scans: List[UUID] = []

        for program in programs:
            # Skip if auto_scan is not enabled
            if not program.auto_scan_enabled:
                continue

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
                    # Use full_audit for scheduled scans (maximum intensity)
                    scan_in = schemas.ScanCreate(
                        scope_id=scope.id,
                        scan_profile=ScanProfile.full_audit
                    )
                    new_scan = await ScanService.create_scan_scheduled(
                        db, scan_in, force_delta=program.delta_scan_enabled
                    )
                    if new_scan:
                        triggered_scans.append(new_scan.id)

        return triggered_scans

    @staticmethod
    async def create_scan_scheduled(
        db: AsyncSession,
        scan_in: schemas.ScanCreate,
        force_delta: bool = False
    ):
        """Create a scheduled scan with optional delta mode override."""
        scope = await crud.get_scope(db, scan_in.scope_id)
        if not scope:
            return None

        program = await crud.get_program(db, scope.program_id)
        if not program:
            return None

        db_scan = await crud.create_scan(db=db, scan=scan_in)

        # Build scan configuration with delta mode override
        scan_config = ScanService._build_scan_config(
            scan_in.scan_profile,
            program,
            str(db_scan.id),
            scope.value,
            specific_port=scope.port,
            force_delta=force_delta
        )

        celery_app.send_task(
            'src.tasks.run_scan',
            args=[scope.value, str(db_scan.id)],
            kwargs={'scan_config': scan_config},
            queue='discovery'
        )

        logger.info(
            f"Created scheduled scan {db_scan.id} with profile={scan_in.scan_profile.value}, "
            f"delta_mode={force_delta}"
        )
        return db_scan

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
                        scan.scan_profile,
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
        scan = await crud.get_scan(db, scan_id)
        if not scan:
            return None

        if scan.status not in [ScanStatus.running, ScanStatus.pending]:
            return scan

        # 1. Revoke Celery Tasks
        i = celery_app.control.inspect()
        active = i.active()
        reserved = i.reserved()

        tasks_to_revoke = []

        def find_tasks(worker_tasks):
            if not worker_tasks:
                return
            for worker, tasks in worker_tasks.items():
                for task in tasks:
                    args = task.get('args', [])
                    if str(scan_id) in [str(arg) for arg in args]:
                        tasks_to_revoke.append(task['id'])

        find_tasks(active)
        find_tasks(reserved)

        if tasks_to_revoke:
            celery_app.control.revoke(tasks_to_revoke, terminate=True)
            logger.info(f"Revoked {len(tasks_to_revoke)} tasks for scan {scan_id}")

        # 2. Update DB
        scan.status = ScanStatus.stopped
        scan.completed_at = datetime.now(timezone.utc)

        db.add(ScanEvent(
            scan_id=scan.id,
            message="Scan manually stopped by user.",
            severity="warning"
        ))

        await db.commit()
        await db.refresh(scan)
        return scan
