"""
Discovery tasks for EASM scan orchestration.
Supports configurable scan depth (fast/deep) with technology-based prioritization.
"""
import logging
from typing import Dict, Any
from celery import chain, group, chord
from src.celery_app import app
from src import tools
from src.utils import log_event, post_to_backend, get_session, HTTP_TIMEOUT

logger = logging.getLogger(__name__)


@app.task(name='src.tasks.run_scan', queue='discovery')
def run_scan(target: str, scan_id: str, scan_config: Dict[str, Any] = None):
    """
    Main entry point for scan orchestration.
    Launches the discovery workflow chain with scan configuration.

    Args:
        target: Domain/IP to scan
        scan_id: UUID of the scan
        scan_config: Configuration dict containing:
            - scan_depth: "fast" or "deep"
            - ports: Port ranges to scan
            - nuclei_rate_limit: Rate limit for Nuclei
            - nuclei_timeout: Timeout for Nuclei
            - nuclei_retries: Retry count
            - enable_full_vuln_scan: Whether to run full scan (deep mode only)
    """
    scan_config = scan_config or {}
    scan_depth = scan_config.get("scan_depth", "fast")

    logger.info(f"Starting scan orchestration for {target} (ID: {scan_id}, depth: {scan_depth})")

    # Update status to running
    try:
        resp = post_to_backend(f"/scans/{scan_id}/results", {"status": "running", "assets": []})
        resp.raise_for_status()
    except Exception as e:
        logger.error(f"Failed to update scan status to running: {e}")

    # Log scan start with mode info
    mode_desc = "Fast (prioritized)" if scan_depth == "fast" else "Deep (comprehensive)"
    log_event(scan_id, f"Scan started in {mode_desc} mode")

    # Build workflow: discovery -> schedule_asset_scans (which handles the rest)
    workflow = chain(
        discovery_task.s(target, scan_id),
        schedule_asset_scans.s(scan_id, scan_config)
    )
    workflow.apply_async()

    return {"status": "started", "scan_id": scan_id, "depth": scan_depth}


@app.task(
    bind=True,
    name='src.tasks.discovery_task',
    queue='discovery',
    autoretry_for=(Exception,),
    retry_kwargs={'max_retries': 3, 'countdown': 60},
    retry_backoff=True
)
def discovery_task(self, target: str, scan_id: str):
    """
    Step 1: Passive discovery using Subfinder
    Discovers subdomains for the target domain.
    """
    logger.info(f"Running discovery on {target}...")
    log_event(scan_id, f"Starting discovery on {target}...")

    try:
        subdomains = tools.run_subfinder(target)

        # Always include the main target
        if target not in subdomains:
            subdomains.append(target)

        log_event(scan_id, f"Discovery completed. Found {len(subdomains)} assets.")

        # Format assets for backend
        assets = [
            {"value": sub, "asset_type": "subdomain", "is_active": True}
            for sub in subdomains
        ]

        # Send discovered assets to backend
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
def schedule_asset_scans(assets: list, scan_id: str, scan_config: Dict[str, Any] = None):
    """
    Step 2: Dynamic scheduling of per-asset scans.
    Creates parallel task chains based on scan depth configuration.

    Workflow per asset:
    - Fast mode: port_scan -> tech_detect -> vuln_scan_prioritized
    - Deep mode: port_scan -> tech_detect -> vuln_scan_prioritized -> vuln_scan_full
    """
    scan_config = scan_config or {}
    scan_depth = scan_config.get("scan_depth", "fast")

    logger.info(f"Scheduling scans for {len(assets)} assets (depth: {scan_depth})...")
    log_event(scan_id, f"Scheduling scans for {len(assets)} assets ({scan_depth} mode).")

    if not assets:
        logger.warning(f"No assets found for scan {scan_id}, finalizing immediately")
        finalize_scan.delay([], scan_id)
        return

    from src.tasks.scan import (
        port_scan_task,
        tech_detect_task,
        vuln_scan_prioritized_task,
        vuln_scan_full_task
    )

    def build_asset_chain(asset: Dict[str, Any]):
        """Build the scan chain for a single asset based on scan depth."""
        if scan_depth == "deep":
            # Deep mode: port -> tech -> vuln_prioritized -> vuln_full
            return chain(
                port_scan_task.s(asset, scan_id, scan_config),
                tech_detect_task.s(scan_id, scan_config),
                vuln_scan_prioritized_task.s(scan_id, scan_config),
                vuln_scan_full_task.s(scan_id, scan_config)
            )
        else:
            # Fast mode: port -> tech -> vuln_prioritized (no full scan)
            return chain(
                port_scan_task.s(asset, scan_id, scan_config),
                tech_detect_task.s(scan_id, scan_config),
                vuln_scan_prioritized_task.s(scan_id, scan_config)
            )

    # Create parallel task chains for all assets
    tasks_group = [build_asset_chain(asset) for asset in assets]

    # Use chord to run all chains in parallel, then finalize
    callback = finalize_scan.s(scan_id)
    chord(group(tasks_group))(callback)


@app.task(name='src.tasks.finalize_scan', queue='discovery')
def finalize_scan(results: list, scan_id: str):
    """
    Final step: Scan finalization.
    Called after all asset scans complete.
    """
    logger.info(f"Scan {scan_id} completed!")

    # Calculate totals from results
    total_vulns = 0
    total_assets = len(results) if results else 0

    for result in (results or []):
        if isinstance(result, dict):
            total_vulns += result.get("vuln_count_prioritized", 0)
            total_vulns += result.get("vuln_count_full", 0)

    # Update scan status
    payload = {"status": "completed", "assets": []}

    try:
        resp = post_to_backend(f"/scans/{scan_id}/results", payload)
        resp.raise_for_status()
        logger.info(f"Scan {scan_id} finalized successfully")
        log_event(scan_id, f"Scan completed. Processed {total_assets} assets, found {total_vulns} vulnerabilities.")
    except Exception as e:
        logger.error(f"Scan finalization error for {scan_id}: {e}", exc_info=True)
        log_event(scan_id, f"Scan finalization failed: {e}", "error")
