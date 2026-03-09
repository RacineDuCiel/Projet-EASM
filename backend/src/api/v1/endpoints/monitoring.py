from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, case
from src.db.session import get_db
from src import models, schemas
from src.models import Program, Asset, Scan, Vulnerability, ScanStatus, Severity, UserRole
import asyncio

# ... (existing code)


router = APIRouter(
    prefix="/monitoring",
    tags=["monitoring"],
    responses={404: {"description": "Not found"}},
)

from src.api.v1.endpoints import auth
from src.models import User

@router.get("/stats")
async def get_stats(db: AsyncSession = Depends(get_db), current_user: User = Depends(auth.get_current_user)):
    """
    Récupère les statistiques globales du projet pour le dashboard de monitoring.
    Optimized: uses combined queries with CASE/WHEN instead of separate COUNT queries.
    """
    if current_user.role == UserRole.admin:
        # Programs
        total_programs = await db.scalar(select(func.count()).select_from(Program))

        # Assets
        total_assets = await db.scalar(select(func.count()).select_from(Asset))

        # Scans - combined query with CASE/WHEN
        scan_stats = await db.execute(
            select(
                func.count().label('total'),
                func.count(case(
                    (Scan.status.in_([ScanStatus.running, ScanStatus.pending]), 1)
                )).label('running'),
                func.count(case(
                    (Scan.status == ScanStatus.failed, 1)
                )).label('failed'),
            ).select_from(Scan)
        )
        scan_row = scan_stats.one()
        total_scans = scan_row.total
        running_scans = scan_row.running
        failed_scans = scan_row.failed

        # Vulnerabilities - combined query with CASE/WHEN
        vuln_stats = await db.execute(
            select(
                func.count().label('total'),
                func.count(case(
                    (Vulnerability.severity == Severity.critical, 1)
                )).label('critical'),
                func.count(case(
                    (Vulnerability.severity == Severity.high, 1)
                )).label('high'),
            ).select_from(Vulnerability)
        )
        vuln_row = vuln_stats.one()
        total_vulns = vuln_row.total
        critical_vulns = vuln_row.critical
        high_vulns = vuln_row.high

    else:
        # Filter by program
        program_id = current_user.program_id

        # Programs (Always 1 for user)
        total_programs = 1

        # Assets (Join Scope)
        total_assets = await db.scalar(
            select(func.count())
            .select_from(Asset)
            .join(models.Scope)
            .where(models.Scope.program_id == program_id)
        )

        # Scans - combined query with CASE/WHEN (filtered by program)
        scan_stats = await db.execute(
            select(
                func.count().label('total'),
                func.count(case(
                    (Scan.status.in_([ScanStatus.running, ScanStatus.pending]), 1)
                )).label('running'),
                func.count(case(
                    (Scan.status == ScanStatus.failed, 1)
                )).label('failed'),
            ).select_from(Scan)
            .join(models.Scope)
            .where(models.Scope.program_id == program_id)
        )
        scan_row = scan_stats.one()
        total_scans = scan_row.total
        running_scans = scan_row.running
        failed_scans = scan_row.failed

        # Vulnerabilities - combined query with CASE/WHEN (filtered by program)
        vuln_stats = await db.execute(
            select(
                func.count().label('total'),
                func.count(case(
                    (Vulnerability.severity == Severity.critical, 1)
                )).label('critical'),
                func.count(case(
                    (Vulnerability.severity == Severity.high, 1)
                )).label('high'),
            ).select_from(Vulnerability)
            .join(Asset)
            .join(models.Scope)
            .where(models.Scope.program_id == program_id)
        )
        vuln_row = vuln_stats.one()
        total_vulns = vuln_row.total
        critical_vulns = vuln_row.critical
        high_vulns = vuln_row.high

    return {
        "programs": {"total": total_programs},
        "assets": {"total": total_assets},
        "scans": {
            "total": total_scans,
            "running": running_scans,
            "failed": failed_scans
        },
        "vulnerabilities": {
            "total": total_vulns,
            "critical": critical_vulns,
            "high": high_vulns
        }
    }

@router.get("/vuln-trend")
async def get_vuln_trend(db: AsyncSession = Depends(get_db), current_user: User = Depends(auth.get_current_user)):
    """
    Returns vulnerability counts grouped by date (last 30 days).
    """
    from datetime import datetime, timedelta
    
    # Simple mock implementation for now as we don't have a history table for vulns yet
    # In a real system, we would query a 'vulnerability_history' or aggregate 'created_at'
    
    # For now, let's return a static trend based on current data to demonstrate the UI
    # Or better, let's group by created_at if we have enough data
    
    # Group by date
    query = select(
        func.date_trunc('day', Vulnerability.created_at).label('date'),
        func.count(Vulnerability.id).label('count')
    ).group_by('date').order_by('date')
    
    if current_user.role != UserRole.admin:
        query = query.join(Asset).join(models.Scope).where(models.Scope.program_id == current_user.program_id)
        
    result = await db.execute(query)
    rows = result.all()
    
    return [{"date": str(row.date).split(' ')[0], "count": row.count} for row in rows]

@router.get("/severity-distribution")
async def get_severity_distribution(db: AsyncSession = Depends(get_db), current_user: User = Depends(auth.get_current_user)):
    """
    Returns full breakdown of vulnerabilities by severity.
    """
    query = select(
        Vulnerability.severity,
        func.count(Vulnerability.id).label('count')
    ).group_by(Vulnerability.severity)
    
    if current_user.role != UserRole.admin:
        query = query.join(Asset).join(models.Scope).where(models.Scope.program_id == current_user.program_id)
        
    result = await db.execute(query)
    rows = result.all()
    
    # Ensure all severities are present even if 0
    counts = {sev.value: 0 for sev in Severity}
    for row in rows:
        counts[row.severity] = row.count
        
    return [{"name": k, "value": v} for k, v in counts.items()]

@router.get("/recent-vulns", response_model=list[schemas.Vulnerability])
async def get_recent_vulnerabilities(db: AsyncSession = Depends(get_db), current_user: User = Depends(auth.get_current_user)):
    """
    Returns latest 5 vulnerabilities (High/Critical).
    """
    query = select(Vulnerability).where(
        Vulnerability.severity.in_([Severity.high, Severity.critical])
    ).order_by(Vulnerability.created_at.desc()).limit(5)
    
    if current_user.role != UserRole.admin:
        query = query.join(Asset).join(models.Scope).where(models.Scope.program_id == current_user.program_id)
        
    result = await db.execute(query)
    return result.scalars().all()

@router.get("/recent-assets", response_model=list[schemas.Asset])
async def get_recent_assets(db: AsyncSession = Depends(get_db), current_user: User = Depends(auth.get_current_user)):
    """
    Returns latest 5 discovered assets.
    """
    from sqlalchemy.orm import selectinload
    
    query = select(Asset).options(
        selectinload(Asset.services),
        selectinload(Asset.vulnerabilities)
    ).order_by(Asset.first_seen.desc()).limit(5)
    
    if current_user.role != UserRole.admin:
        query = query.join(models.Scope).where(models.Scope.program_id == current_user.program_id)
        
    result = await db.execute(query)
    return result.scalars().all()

@router.get("/workers")
async def get_worker_status(current_user: User = Depends(auth.get_current_user)):
    """
    Get Celery workers status.
    Only for admins.
    """
    if current_user.role != UserRole.admin:
        return []

    from src.core.celery_utils import celery_app

    # Inspect workers (blocking call wrapped in asyncio.to_thread)
    i = celery_app.control.inspect()

    # Ping workers to see who is alive
    active = await asyncio.to_thread(i.ping)
    if not active:
        return []
        
    workers = []
    for worker_name, response in active.items():
        workers.append({
            "name": worker_name,
            "status": "online" if response else "offline",
            "last_seen": "now" # In a real app we might track this
        })
        
    return workers
