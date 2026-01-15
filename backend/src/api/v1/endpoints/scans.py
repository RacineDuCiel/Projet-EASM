from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from uuid import UUID
from slowapi import Limiter
from slowapi.util import get_remote_address
from src import crud, schemas
from src.db import session as database
from src.services.scan_service import ScanService
from src.services.asset_service import AssetService

router = APIRouter(
    prefix="/scans",
    tags=["scans"],
    responses={404: {"description": "Not found"}},
)

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

# Services
asset_service = AssetService()

from src.api.v1.endpoints import auth
from src.models import User, UserRole

@router.post("/", response_model=schemas.Scan)
@limiter.limit("10/minute")
async def create_scan(
    request: Request,
    scan: schemas.ScanCreate,
    db: AsyncSession = Depends(database.get_db),
    current_user: User = Depends(auth.get_current_user)
):
    if current_user.role == UserRole.admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admins cannot launch scans. This is an operational task for users."
        )

    db_scan = await ScanService.create_scan(db, scan)
    if not db_scan:
        raise HTTPException(status_code=404, detail="Scope not found")
    return db_scan

@router.post("/{scan_id}/results")
async def receive_scan_results(scan_id: UUID, result: schemas.ScanResult, db: AsyncSession = Depends(database.get_db)):
    # 1. Get Scan
    scan = await ScanService.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # 2. Process Assets (Simple creation for results)
    for asset_data in result.assets:
        await asset_service.create_asset_simple(db, asset_data, scan.scope_id)
        
    # 3. Update Scan Status
    await ScanService.update_status(db, scan_id, result.status)
    
    return {"status": "ok"}

@router.post("/{scan_id}/assets")
async def add_scan_assets(
    scan_id: UUID, 
    assets: List[schemas.AssetCreate], 
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(database.get_db)
):
    """
    Endpoint pour ajouter des assets au fil de l'eau (incremental updates).
    N'affecte pas le statut du scan.
    Supporte le streaming temps réel de vulnérabilités.
    """
    try:
        processed_count, error_count = await asset_service.process_asset_chunk(
            db, scan_id, assets, background_tasks
        )
        return {"status": "assets_added", "count": processed_count, "errors": error_count}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/{scan_id}/vulnerabilities")
async def add_vulnerability_stream(
    scan_id: UUID,
    vulnerability: schemas.VulnerabilityStreamCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(database.get_db)
):
    """
    Endpoint dédié au streaming temps réel de vulnérabilités.
    Permet aux workers de remonter instantanément chaque vulnérabilité découverte.
    """
    try:
        # Vérifier que le scan existe
        scan = await ScanService.get_scan(db, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Créer ou mettre à jour l'asset et ajouter la vulnérabilité
        db_vuln = await asset_service.add_vulnerability_realtime(
            db, scan.scope_id, vulnerability, background_tasks
        )
        
        return {
            "status": "vulnerability_added",
            "vulnerability_id": str(db_vuln.id),
            "asset_id": str(db_vuln.asset_id)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to add vulnerability: {str(e)}")

@router.post("/{scan_id}/tech-detect")
async def update_tech_detection(
    scan_id: UUID,
    tech_result: schemas.TechDetectionResult,
    db: AsyncSession = Depends(database.get_db)
):
    """
    Endpoint for workers to report technology detection results.
    Updates the Service model with detected technologies.
    """
    try:
        scan = await ScanService.get_scan(db, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Update service with tech detection data
        service = await crud.update_service_technologies(
            db,
            scope_id=scan.scope_id,
            asset_value=tech_result.asset_value,
            port=tech_result.port,
            technologies=tech_result.technologies,
            web_server=tech_result.web_server,
            waf_detected=tech_result.waf_detected,
            tls_version=tech_result.tls_version,
            response_time_ms=tech_result.response_time_ms
        )

        return {
            "status": "ok",
            "service_id": str(service.id) if service else None
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update tech detection: {str(e)}")


@router.post("/{scan_id}/events", response_model=schemas.ScanEvent)
async def add_scan_event(scan_id: UUID, event: schemas.ScanEventCreate, db: AsyncSession = Depends(database.get_db)):
    # 1. Get Scan
    scan = await ScanService.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # 2. Create Event
    return await crud.create_scan_event(db, event, scan_id)

@router.get("/{scan_id}/events", response_model=List[schemas.ScanEvent])
async def read_scan_events(scan_id: UUID, db: AsyncSession = Depends(database.get_db)):
    scan = await ScanService.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan.events


@router.get("/profiles", response_model=List[schemas.ScanProfileInfo])
async def get_scan_profiles():
    """
    Return available scan profiles with their descriptions.
    Used by frontend to display profile selection UI.
    """
    return ScanService.get_available_profiles()


@router.get("/", response_model=List[schemas.Scan])
async def read_scans(
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(database.get_db),
    current_user: User = Depends(auth.get_current_user)
):
    if current_user.role == UserRole.admin:
        return await ScanService.get_scans(db, skip=skip, limit=limit)
    else:
        return await ScanService.get_scans_by_program(db, program_id=current_user.program_id, skip=skip, limit=limit)

@router.post("/check-schedules")
async def check_schedules(db: AsyncSession = Depends(database.get_db)):
    """
    Triggered by Celery Beat to check for scheduled scans.
    """
    triggered = await ScanService.check_scheduled_scans(db)
    return {"status": "ok", "triggered_scans": triggered}

@router.get("/{scan_id}", response_model=schemas.Scan)
async def read_scan(scan_id: UUID, db: AsyncSession = Depends(database.get_db)):
    scan = await ScanService.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@router.post("/{scan_id}/stop", response_model=schemas.Scan)
async def stop_scan(scan_id: UUID, db: AsyncSession = Depends(database.get_db), current_user: User = Depends(auth.get_current_user)):
    if current_user.role != UserRole.admin:
        raise HTTPException(status_code=403, detail="Only admins can stop scans")
        
    scan = await ScanService.stop_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
