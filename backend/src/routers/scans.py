from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from uuid import UUID
from celery import Celery
import os
from slowapi import Limiter
from slowapi.util import get_remote_address
from .. import crud, schemas, database
from ..notifications.manager import NotificationManager

router = APIRouter(
    prefix="/scans",
    tags=["scans"],
    responses={404: {"description": "Not found"}},
)

# Celery setup (should be centralized)
celery_app = Celery('worker', broker=os.getenv("REDIS_URL"))
notification_manager = NotificationManager()

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

@router.post("/", response_model=schemas.Scan)
@limiter.limit("10/minute")  # Limite stricte pour éviter les abus
async def create_scan(
    request: Request,
    scan: schemas.ScanCreate,
    db: AsyncSession = Depends(database.get_db)
):
    # 1. Verify Scope exists
    scope = await crud.get_scope(db, scan.scope_id)
    if not scope:
        raise HTTPException(status_code=404, detail="Scope not found")

    # 2. Create Scan record in DB
    db_scan = await crud.create_scan(db=db, scan=scan)
    
    # 3. Trigger Celery task
    # We pass the scan_id so the worker can update the status
    task = celery_app.send_task('src.tasks.run_scan', args=[scope.value, str(db_scan.id)], queue='discovery')
    
    return db_scan

@router.post("/{scan_id}/results")
async def receive_scan_results(scan_id: UUID, result: schemas.ScanResult, db: AsyncSession = Depends(database.get_db)):
    # 1. Get Scan
    scan = await crud.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # 2. Process Assets
    for asset_data in result.assets:
        # We need to ensure asset_data has the right structure for create_asset
        # asset_data is AssetBase, we need to pass it
        await crud.create_asset(db, asset_data, scan.scope_id)
        
    # 3. Update Scan Status
    await crud.update_scan_status(db, scan_id, result.status)
    
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
    """
    import logging
    logger = logging.getLogger(__name__)
    
    # 1. Get Scan
    scan = await crud.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # 2. Process Assets
    processed_count = 0
    error_count = 0
    
    for asset_data in assets:
        try:
            logger.info(f"Processing asset: {asset_data.value} with {len(asset_data.vulnerabilities)} vulnerabilities")
            logger.debug(f"Full asset payload: {asset_data.model_dump_json()}")
            
            # create_asset returns (db_asset, new_vulns)
            db_asset, new_vulns = await crud.create_asset(db, asset_data, scan.scope_id)
            
            logger.info(f"Successfully created/updated asset {db_asset.value}. New vulnerabilities: {len(new_vulns)}")
            
            # 3. Trigger Notifications (Background)
            if new_vulns:
                background_tasks.add_task(notification_manager.notify_new_vulnerabilities, new_vulns)
            
            processed_count += 1
        except Exception as e:
            error_count += 1
            logger.error(f"Failed to process asset {asset_data.value}: {e}", exc_info=True)
            # Continue processing other assets instead of failing completely
        
    logger.info(f"Asset processing complete. Processed: {processed_count}, Errors: {error_count}")
    return {"status": "assets_added", "count": processed_count, "errors": error_count}

@router.post("/{scan_id}/events", response_model=schemas.ScanEvent)
async def add_scan_event(scan_id: UUID, event: schemas.ScanEventCreate, db: AsyncSession = Depends(database.get_db)):
    # 1. Get Scan
    scan = await crud.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # 2. Create Event
    return await crud.create_scan_event(db, event, scan_id)

@router.get("/{scan_id}/events", response_model=List[schemas.ScanEvent])
async def read_scan_events(scan_id: UUID, db: AsyncSession = Depends(database.get_db)):
    scan = await crud.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan.events

@router.get("/", response_model=List[schemas.Scan])
async def read_scans(skip: int = 0, limit: int = 100, db: AsyncSession = Depends(database.get_db)):
    return await crud.get_scans(db, skip=skip, limit=limit)

@router.get("/{scan_id}", response_model=schemas.Scan)
async def read_scan(scan_id: UUID, db: AsyncSession = Depends(database.get_db)):
    scan = await crud.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
