import requests
import logging
from celery import chain, group, chord
from src.celery_app import app, BACKEND_URL
from src import tools
from src.utils import log_event, HTTP_TIMEOUT

logger = logging.getLogger(__name__)

@app.task(name='src.tasks.run_scan', queue='discovery')
def run_scan(target, scan_id):
    """
    Point d'entrée principal (Legacy/Wrapper).
    Lance l'orchestration du scan.
    """
    logger.info(f"Démarrage de l'orchestration pour {target} (ID: {scan_id})")
    
    # Update status to running
    try:
        requests.post(
            f"{BACKEND_URL}/scans/{scan_id}/results",
            json={"status": "running", "assets": []},
            timeout=HTTP_TIMEOUT
        )
    except Exception as e:
        logger.error(f"Failed to update scan status to running: {e}")

    workflow = chain(
        discovery_task.s(target, scan_id),
        schedule_asset_scans.s(scan_id)
    )
    workflow.apply_async()
    return {"status": "started", "scan_id": scan_id}

@app.task(
    bind=True,
    name='src.tasks.discovery_task',
    queue='discovery',
    autoretry_for=(requests.RequestException, requests.Timeout),
    retry_kwargs={'max_retries': 3, 'countdown': 60},
    retry_backoff=True
)
def discovery_task(self, target, scan_id):
    """
    Etape 1: Découverte passive (Subfinder)
    """
    logger.info(f"Discovery sur {target}...")
    log_event(scan_id, f"Starting discovery on {target}...")
    
    try:
        subdomains = tools.run_subfinder(target)
        
        if target not in subdomains:
            subdomains.append(target)
            
        log_event(scan_id, f"Discovery completed. Found {len(subdomains)} assets.")
            
        assets = []
        for sub in subdomains:
            assets.append({
                "value": sub,
                "asset_type": "subdomain",
                "is_active": True
            })
            
        try:
            resp = requests.post(
                f"{BACKEND_URL}/scans/{scan_id}/assets",
                json=assets,
                timeout=HTTP_TIMEOUT
            )
            resp.raise_for_status()
            logger.info(f"Sent {len(assets)} assets to backend for scan {scan_id}")
        except Exception as e:
            logger.error(f"Erreur envoi assets: {e}", exc_info=True)
            raise
            
        return assets
    except Exception as e:
        logger.error(f"Discovery failed for {target}: {e}", exc_info=True)
        log_event(scan_id, f"Discovery failed: {str(e)}", "error")
        raise

@app.task(name='src.tasks.schedule_asset_scans', queue='discovery')
def schedule_asset_scans(assets, scan_id):
    """
    Etape 2: Planification dynamique des scans par asset.
    """
    logger.info(f"Planification des scans pour {len(assets)} assets...")
    log_event(scan_id, f"Scheduling scans for {len(assets)} assets.")
    
    if not assets:
        logger.warning(f"No assets found for scan {scan_id}, finalizing immediately")
        finalize_scan.delay([], scan_id)
        return
    
    # Import here to avoid circular imports if scan tasks are in another module
    from src.tasks.scan import port_scan_task, vuln_scan_task
    
    tasks_group = []
    
    for asset in assets:
        asset_pipeline = chain(
            port_scan_task.s(asset, scan_id),
            vuln_scan_task.s(scan_id)
        )
        tasks_group.append(asset_pipeline)
        
    callback = finalize_scan.s(scan_id)
    chord(group(tasks_group))(callback)

@app.task(name='src.tasks.finalize_scan', queue='discovery')
def finalize_scan(results, scan_id):
    """
    Etape 4: Finalisation du scan
    """
    logger.info(f"Scan {scan_id} terminé !")
    
    payload = {
        "status": "completed",
        "assets": []
    }
    
    try:
        resp = requests.post(
            f"{BACKEND_URL}/scans/{scan_id}/results",
            json=payload,
            timeout=HTTP_TIMEOUT
        )
        resp.raise_for_status()
        logger.info(f"Scan {scan_id} finalized successfully")
        log_event(scan_id, "Scan completed successfully.")
    except Exception as e:
        logger.error(f"Erreur finalisation scan {scan_id}: {e}", exc_info=True)
        log_event(scan_id, f"Scan finalization failed: {e}", "error")
