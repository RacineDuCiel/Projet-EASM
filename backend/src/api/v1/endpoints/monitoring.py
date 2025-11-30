from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from src.db.session import get_db
from src.models import Program, Asset, Scan, Vulnerability, ScanStatus, Severity

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
    """
    if current_user.role == "admin":
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
        
        # Scans (Join Scope)
        total_scans = await db.scalar(
            select(func.count())
            .select_from(Scan)
            .join(models.Scope)
            .where(models.Scope.program_id == program_id)
        )
        running_scans = await db.scalar(
            select(func.count())
            .select_from(Scan)
            .join(models.Scope)
            .where(models.Scope.program_id == program_id)
            .where(Scan.status == ScanStatus.running)
        )
        failed_scans = await db.scalar(
            select(func.count())
            .select_from(Scan)
            .join(models.Scope)
            .where(models.Scope.program_id == program_id)
            .where(Scan.status == ScanStatus.failed)
        )
        
        # Vulnerabilities (Join Asset -> Scope)
        total_vulns = await db.scalar(
            select(func.count())
            .select_from(Vulnerability)
            .join(Asset)
            .join(models.Scope)
            .where(models.Scope.program_id == program_id)
        )
        critical_vulns = await db.scalar(
            select(func.count())
            .select_from(Vulnerability)
            .join(Asset)
            .join(models.Scope)
            .where(models.Scope.program_id == program_id)
            .where(Vulnerability.severity == Severity.critical)
        )
        high_vulns = await db.scalar(
            select(func.count())
            .select_from(Vulnerability)
            .join(Asset)
            .join(models.Scope)
            .where(models.Scope.program_id == program_id)
            .where(Vulnerability.severity == Severity.high)
        )

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
