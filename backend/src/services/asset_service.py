from uuid import UUID
from typing import List, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import BackgroundTasks
from src import crud, schemas, models
from src.notifications.manager import NotificationManager

class AssetService:
    def __init__(self):
        self.notification_manager = NotificationManager()

    async def process_asset_chunk(
        self, 
        db: AsyncSession, 
        scan_id: UUID, 
        assets: List[schemas.AssetCreate], 
        background_tasks: BackgroundTasks
    ) -> Tuple[int, int]:
        """
        Process a chunk of assets: create/update in DB and trigger notifications.
        Returns (processed_count, error_count).
        """
        import logging
        logger = logging.getLogger(__name__)

        # 1. Get Scan to know the scope_id
        scan = await crud.get_scan(db, scan_id)
        if not scan:
            raise ValueError("Scan not found")

        processed_count = 0
        error_count = 0

        for asset_data in assets:
            try:
                # create_asset returns (db_asset, new_vulns)
                # Logic is currently in CRUD, we will keep it there for now as it's atomic DB operation
                # Ideally, complex logic should move here, but CRUD.create_asset does a lot of DB checks.
                # For Phase 1, we wrap the CRUD call.
                db_asset, new_vulns = await crud.create_asset(db, asset_data, scan.scope_id)
                
                # Trigger Notifications (Background)
                if new_vulns:
                    background_tasks.add_task(self.notification_manager.notify_new_vulnerabilities, new_vulns)
                
                processed_count += 1
            except Exception as e:
                error_count += 1
                logger.error(f"Failed to process asset {asset_data.value}: {e}", exc_info=True)
        
        return processed_count, error_count

    async def create_asset_simple(self, db: AsyncSession, asset: schemas.AssetCreate, scope_id: UUID):
        return await crud.create_asset(db, asset, scope_id)
