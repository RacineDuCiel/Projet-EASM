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
        from sqlalchemy import update
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
                db_asset, new_vulns = await crud.create_asset(db, asset_data, scan.scope_id)

                # Trigger Notifications (Background)
                if new_vulns:
                    background_tasks.add_task(self.notification_manager.notify_new_vulnerabilities, new_vulns)

                processed_count += 1
            except Exception as e:
                error_count += 1
                logger.error(f"Failed to process asset {asset_data.value}: {e}", exc_info=True)

        # Update assets_scanned counter on the scan
        if processed_count > 0:
            await db.execute(
                update(models.Scan)
                .where(models.Scan.id == scan_id)
                .values(assets_scanned=models.Scan.assets_scanned + processed_count)
            )
            await db.commit()

        return processed_count, error_count

    async def create_asset_simple(self, db: AsyncSession, asset: schemas.AssetCreate, scope_id: UUID):
        # crud.create_asset returns (asset, new_vulns) tuple
        db_asset, _ = await crud.create_asset(db, asset, scope_id)
        return db_asset

    async def add_vulnerability_realtime(
        self,
        db: AsyncSession,
        scope_id: UUID,
        scan_id: UUID,
        vuln_data: schemas.VulnerabilityStreamCreate,
        background_tasks: BackgroundTasks
    ) -> models.Vulnerability:
        """
        Ajoute une vulnérabilité en temps réel lors d'un scan.
        Crée l'asset s'il n'existe pas, puis ajoute la vulnérabilité.
        Chaque vulnérabilité est liée au scan qui l'a découverte.
        """
        import logging
        logger = logging.getLogger(__name__)

        # 1. Chercher ou créer l'asset
        db_asset = await crud.get_asset_by_value(db, vuln_data.asset_value, scope_id)

        if not db_asset:
            # Créer l'asset
            asset_create = schemas.AssetCreate(
                value=vuln_data.asset_value,
                asset_type=vuln_data.asset_type,
                is_active=True,
                services=[],
                vulnerabilities=[]
            )
            db_asset, _ = await crud.create_asset(db, asset_create, scope_id)
            logger.info(f"Created new asset {vuln_data.asset_value} for streaming vulnerability")

        # 2. Gérer le service si un port est spécifié
        service_id = None
        if vuln_data.port:
            # Chercher ou créer le service
            db_service = await crud.get_or_create_service(
                db,
                db_asset.id,
                vuln_data.port,
                vuln_data.service_name or "unknown"
            )
            service_id = db_service.id

        # 3. Vérifier si la vulnérabilité existe déjà pour CE scan (deduplication par scan)
        existing_vuln = await crud.get_vulnerability_by_scan_and_title(
            db, scan_id, vuln_data.title
        )

        if existing_vuln:
            logger.debug(f"Vulnerability '{vuln_data.title}' already exists for scan {scan_id}")
            return existing_vuln

        # 4. Créer la vulnérabilité liée au scan
        vuln_create = models.Vulnerability(
            asset_id=db_asset.id,
            service_id=service_id,
            scan_id=scan_id,
            title=vuln_data.title,
            severity=vuln_data.severity,
            description=vuln_data.description,
            status=models.VulnStatus.open
        )

        db.add(vuln_create)

        # 5. Incrémenter le compteur de vulnérabilités du scan
        from sqlalchemy import update
        await db.execute(
            update(models.Scan)
            .where(models.Scan.id == scan_id)
            .values(vulns_found=models.Scan.vulns_found + 1)
        )

        await db.commit()
        await db.refresh(vuln_create)

        logger.info(f"Streamed new vulnerability: {vuln_data.title} on {vuln_data.asset_value} (scan: {scan_id})")

        # 5. Notification en arrière-plan
        background_tasks.add_task(
            self.notification_manager.notify_new_vulnerabilities,
            [vuln_create]
        )

        return vuln_create

