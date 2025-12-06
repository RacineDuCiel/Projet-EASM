"""
Discovery tasks for EASM scan orchestration.
"""
import logging
from celery import chain, group, chord
from src.celery_app import app
from src import tools
from src.utils import log_event, post_to_backend, get_session, HTTP_TIMEOUT

logger = logging.getLogger(__name__)


@app.task(name='src.tasks.run_scan', queue='discovery')
def run_scan(target, scan_id):
    """
    Main entry point for scan orchestration.
    Launches the discovery workflow chain.
    """
    logger.info(f"Starting scan orchestration for {target} (ID: {scan_id})")
    
    # Update status to running using pooled session
    try:
        resp = post_to_backend(f"/scans/{scan_id}/results", {"status": "running", "assets": []})
        resp.raise_for_status()
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
    autoretry_for=(Exception,),
    retry_kwargs={'max_retries': 3, 'countdown': 60},
    retry_backoff=True
)
def discovery_task(self, target, scan_id):
    """
    Step 1: Passive discovery using Subfinder
    """
    logger.info(f"Running discovery on {target}...")
    log_event(scan_id, f"Starting discovery on {target}...")
    
    try:
        subdomains = tools.run_subfinder(target)
        
        if target not in subdomains:
            subdomains.append(target)
            
        log_event(scan_id, f"Discovery completed. Found {len(subdomains)} assets.")
            
        assets = [
            {"value": sub, "asset_type": "subdomain", "is_active": True}
            for sub in subdomains
        ]
            
        try:
            resp = post_to_backend(f"/scans/{scan_id}/assets", assets)
            resp.raise_for_status()
            logger.info(f"Sent {len(assets)} assets to backend for scan {scan_id}")
        except Exception as e:
            logger.error(f"Error sending assets: {e}", exc_info=True)
            raise
            
        return assets
    except Exception as e:
        logger.error(f"Discovery failed for {target}: {e}", exc_info=True)
        log_event(scan_id, f"Discovery failed: {str(e)}", "error")
        raise


@app.task(name='src.tasks.schedule_asset_scans', queue='discovery')
def schedule_asset_scans(assets, scan_id):
    """
    Step 2: Dynamic scheduling of per-asset scans.
    """
    logger.info(f"Scheduling scans for {len(assets)} assets...")
    log_event(scan_id, f"Scheduling scans for {len(assets)} assets.")
    
    if not assets:
        logger.warning(f"No assets found for scan {scan_id}, finalizing immediately")
        finalize_scan.delay([], scan_id)
        return
    
    from src.tasks.scan import port_scan_task, vuln_scan_task
    
    tasks_group = [
        chain(port_scan_task.s(asset, scan_id), vuln_scan_task.s(scan_id))
        for asset in assets
    ]
        
    callback = finalize_scan.s(scan_id)
    chord(group(tasks_group))(callback)


@app.task(name='src.tasks.finalize_scan', queue='discovery')
def finalize_scan(results, scan_id):
    """
    Step 4: Scan finalization
    """
    logger.info(f"Scan {scan_id} completed!")
    
    payload = {"status": "completed", "assets": []}
    
    try:
        resp = post_to_backend(f"/scans/{scan_id}/results", payload)
        resp.raise_for_status()
        logger.info(f"Scan {scan_id} finalized successfully")
        log_event(scan_id, "Scan completed successfully.")
    except Exception as e:
        logger.error(f"Scan finalization error for {scan_id}: {e}", exc_info=True)
        log_event(scan_id, f"Scan finalization failed: {e}", "error")
