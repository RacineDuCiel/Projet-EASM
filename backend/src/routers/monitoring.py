from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from ..database import get_db
from ..models import Program, Asset, Scan, Vulnerability, ScanStatus, Severity

router = APIRouter(
    prefix="/monitoring",
    tags=["monitoring"],
    responses={404: {"description": "Not found"}},
)

@router.get("/stats")
async def get_stats(db: AsyncSession = Depends(get_db)):
    """
    Récupère les statistiques globales du projet pour le dashboard de monitoring.
    """
    # Programs
    total_programs = await db.scalar(select(func.count()).select_from(Program))
    
    # Assets
    total_assets = await db.scalar(select(func.count()).select_from(Asset))
    
    # Scans
    total_scans = await db.scalar(select(func.count()).select_from(Scan))
    running_scans = await db.scalar(select(func.count()).select_from(Scan).where(Scan.status == ScanStatus.running))
    failed_scans = await db.scalar(select(func.count()).select_from(Scan).where(Scan.status == ScanStatus.failed))
    
    # Vulnerabilities
    total_vulns = await db.scalar(select(func.count()).select_from(Vulnerability))
    critical_vulns = await db.scalar(select(func.count()).select_from(Vulnerability).where(Vulnerability.severity == Severity.critical))
    high_vulns = await db.scalar(select(func.count()).select_from(Vulnerability).where(Vulnerability.severity == Severity.high))

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
