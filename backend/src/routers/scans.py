from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from uuid import UUID
from celery import Celery
import os
from .. import crud, schemas, database

router = APIRouter(
    prefix="/scans",
    tags=["scans"],
    responses={404: {"description": "Not found"}},
)

# Celery setup (should be centralized)
celery_app = Celery('worker', broker=os.getenv("REDIS_URL"))

@router.post("/", response_model=schemas.Scan)
async def create_scan(scan: schemas.ScanCreate, db: AsyncSession = Depends(database.get_db)):
    # 1. Verify Scope exists
    scope = await crud.get_scope(db, scan.scope_id)
    if not scope:
        raise HTTPException(status_code=404, detail="Scope not found")

    # 2. Create Scan record in DB
    db_scan = await crud.create_scan(db=db, scan=scan)
    
    # 3. Trigger Celery task
    # We pass the scan_id so the worker can update the status
    task = celery_app.send_task('src.tasks.run_scan', args=[scope.value, str(db_scan.id)])
    
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
async def add_scan_assets(scan_id: UUID, assets: List[schemas.AssetCreate], db: AsyncSession = Depends(database.get_db)):
    """
    Endpoint pour ajouter des assets au fil de l'eau (incremental updates).
    N'affecte pas le statut du scan.
    """
    # 1. Get Scan
    scan = await crud.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # 2. Process Assets
    for asset_data in assets:
        await crud.create_asset(db, asset_data, scan.scope_id)
        
    return {"status": "assets_added", "count": len(assets)}

@router.get("/", response_model=List[schemas.Scan])
async def read_scans(skip: int = 0, limit: int = 100, db: AsyncSession = Depends(database.get_db)):
    return await crud.get_scans(db, skip=skip, limit=limit)
