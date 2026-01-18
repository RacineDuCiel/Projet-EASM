"""
Discovery tasks for EASM scan orchestration.
Supports profile-based scanning with phase-based execution and delta scanning.
"""
import logging
from typing import Dict, Any, List
from celery import chain, group, chord
from src.celery_app import app
from src import tools
from src.utils import log_event, post_to_backend, get_session, HTTP_TIMEOUT

logger = logging.getLogger(__name__)


@app.task(name='src.tasks.run_scan', queue='discovery')
def run_scan(target: str, scan_id: str, scan_config: Dict[str, Any] = None):
    """
    Main entry point for scan orchestration.
    Uses profile-based configuration with phase-based execution.

    Args:
        target: Domain/IP to scan
        scan_id: UUID of the scan
        scan_config: Configuration dict containing:
            - scan_profile: Profile name (discovery, quick_assessment, etc.)
            - phases: List of phase names to execute
            - ports: Port ranges to scan
            - nuclei_rate_limit, nuclei_timeout, nuclei_retries
            - run_prioritized_templates, run_full_templates
            - passive_recon_enabled, passive_extended_enabled
            - is_delta_scan, delta_threshold_hours
            - api_keys: Dict of API keys for passive recon
    """
    scan_config = scan_config or {}
    scan_profile = scan_config.get("scan_profile", "standard_assessment")
    phases = scan_config.get("phases", ["asset_discovery", "service_enumeration", "tech_detection", "vuln_assessment"])
    passive_recon_enabled = scan_config.get("passive_recon_enabled", True)
    is_delta_scan = scan_config.get("is_delta_scan", False)

    logger.info(f"Starting scan orchestration for {target} (ID: {scan_id}, profile: {scan_profile})")

    # Update status to running
    try:
        resp = post_to_backend(f"/scans/{scan_id}/results", {"status": "running", "assets": []})
        resp.raise_for_status()
    except Exception as e:
        logger.error(f"Failed to update scan status to running: {e}")

    # Log scan start with profile info
    profile_display = _get_profile_display_name(scan_profile)
    delta_info = " (delta mode)" if is_delta_scan else ""
    passive_info = " + Passive Recon" if passive_recon_enabled else ""
    log_event(scan_id, f"Scan started with profile: {profile_display}{delta_info}{passive_info}")
    log_event(scan_id, f"Phases: {', '.join(phases)}")

    # Launch passive recon in parallel (fire and forget, doesn't block main workflow)
    if passive_recon_enabled:
        from src.tasks.passive_recon import passive_recon_orchestrator
        passive_recon_orchestrator.delay(target, scan_id, scan_config)
        logger.info(f"Passive recon launched for {target}")

    # Check if asset_discovery phase is enabled
    if "asset_discovery" in phases:
        # Build main workflow: discovery -> schedule_asset_scans
        workflow = chain(
            discovery_task.s(target, scan_id),
            schedule_asset_scans.s(scan_id, scan_config)
        )
        workflow.apply_async()
    else:
        # Skip discovery, just use the target directly
        assets = [{"value": target, "asset_type": "subdomain", "is_active": True}]
        schedule_asset_scans.delay(assets, scan_id, scan_config)

    return {
        "status": "started",
        "scan_id": scan_id,
        "profile": scan_profile,
        "phases": phases,
        "passive_recon": passive_recon_enabled,
        "delta_scan": is_delta_scan
    }


def _get_profile_display_name(profile: str) -> str:
    """Get human-readable profile name."""
    display_names = {
        "discovery": "Discovery",
        "quick_assessment": "Quick Assessment",
        "standard_assessment": "Standard Assessment",
        "full_audit": "Full Audit",
        "continuous_monitoring": "Continuous Monitoring",
    }
    return display_names.get(profile, profile)


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
    Phase 1: Asset Discovery using Subfinder
    Discovers subdomains for the target domain.
    """
    logger.info(f"Running discovery on {target}...")
    log_event(scan_id, f"Phase 1: Starting asset discovery on {target}...")

    try:
        result = tools.run_subfinder(target)

        if not result.is_success:
            error_msg = result.error.message if result.error else "Unknown error"
            logger.warning(f"Subfinder failed: {error_msg}, trying alternative discovery")

        subdomains = []
        if result.is_success:
            subdomains = result.data.subdomains

        if not subdomains:
            logger.info("Trying aggregated subdomain discovery...")
            agg_result = tools.aggregate_subdomain_discovery(
                domain=target,
                use_amass=False,
                use_findomain=True,
                use_assetfinder=True,
                parallel=True
            )
            subdomains = agg_result.get("subdomains", [])

        if target not in subdomains:
            subdomains.append(target)

        log_event(scan_id, f"Asset discovery completed. Found {len(subdomains)} assets.")

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
        log_event(scan_id, f"Asset discovery failed: {str(e)}", "error")
        raise


@app.task(name='src.tasks.schedule_asset_scans', queue='discovery')
def schedule_asset_scans(assets: list, scan_id: str, scan_config: Dict[str, Any] = None):
    """
    Phase-based scheduling of per-asset scans.
    Creates parallel task chains based on phases configuration.
    Supports delta scanning - skips recently scanned assets.
    """
    scan_config = scan_config or {}
    phases = scan_config.get("phases", ["asset_discovery", "service_enumeration", "tech_detection", "vuln_assessment"])
    is_delta_scan = scan_config.get("is_delta_scan", False)
    delta_threshold_hours = scan_config.get("delta_threshold_hours", 24)

    logger.info(f"Scheduling scans for {len(assets)} assets (phases: {phases})...")

    if not assets:
        logger.warning(f"No assets found for scan {scan_id}, finalizing immediately")
        finalize_scan.delay([], scan_id)
        return

    # Delta scanning: filter out recently scanned assets
    if is_delta_scan:
        assets, skipped_count = _filter_stale_assets(assets, scan_id, delta_threshold_hours)
        if skipped_count > 0:
            log_event(scan_id, f"Delta mode: scanning {len(assets)} assets, skipped {skipped_count} recently scanned")
        if not assets:
            log_event(scan_id, "No stale assets to scan in delta mode")
            finalize_scan.delay([], scan_id)
            return

    log_event(scan_id, f"Scheduling scans for {len(assets)} assets")

    from src.tasks.scan import (
        port_scan_task,
        tech_detect_task,
        vuln_scan_prioritized_task,
        vuln_scan_full_task
    )

    def build_asset_chain(asset: Dict[str, Any]):
        """Build the scan chain for a single asset based on phases."""
        chain_tasks = []

        # Phase 2: Service Enumeration
        if "service_enumeration" in phases:
            chain_tasks.append(port_scan_task.s(asset, scan_id, scan_config))

        # Phase 3: Tech Detection
        if "tech_detection" in phases:
            if chain_tasks:
                chain_tasks.append(tech_detect_task.s(scan_id, scan_config))
            else:
                chain_tasks.append(tech_detect_task.s(asset, scan_id, scan_config))

        # Phase 4: Vulnerability Assessment
        if "vuln_assessment" in phases:
            if chain_tasks:
                chain_tasks.append(vuln_scan_prioritized_task.s(scan_id, scan_config))
            else:
                chain_tasks.append(vuln_scan_prioritized_task.s(asset, scan_id, scan_config))

        # Phase 5: Deep Analysis
        if "deep_analysis" in phases:
            if chain_tasks:
                chain_tasks.append(vuln_scan_full_task.s(scan_id, scan_config))
            else:
                chain_tasks.append(vuln_scan_full_task.s(asset, scan_id, scan_config))

        if chain_tasks:
            return chain(*chain_tasks)
        return None

    # Create parallel task chains for all assets
    task_chains = [c for c in (build_asset_chain(asset) for asset in assets) if c]

    if task_chains:
        # Use chord to run all chains in parallel, then finalize
        callback = finalize_scan.s(scan_id)
        chord(group(task_chains))(callback)
    else:
        # No tasks to run, just finalize
        finalize_scan.delay([], scan_id)


def _filter_stale_assets(assets: List[Dict], scan_id: str, threshold_hours: int) -> tuple:
    """
    Filter assets for delta scanning.
    Returns (assets_to_scan, skipped_count).

    Queries the backend to determine which assets haven't been scanned
    within the threshold period.
    """
    if not assets:
        return assets, 0

    # Extract asset values for the query
    asset_values = [asset.get("value") for asset in assets if asset.get("value")]

    if not asset_values:
        return assets, 0

    try:
        # Query backend for stale assets
        resp = post_to_backend(
            f"/scans/{scan_id}/stale-assets",
            {
                "asset_values": asset_values,
                "threshold_hours": threshold_hours
            }
        )
        resp.raise_for_status()
        data = resp.json()

        stale_values = {item["value"] for item in data.get("stale_assets", [])}

        # Filter assets to only include stale ones
        stale_assets = [asset for asset in assets if asset.get("value") in stale_values]
        skipped_count = len(assets) - len(stale_assets)

        logger.info(
            f"Delta scan filter: {len(stale_assets)} stale assets to scan, "
            f"{skipped_count} recently scanned assets skipped"
        )

        return stale_assets, skipped_count

    except Exception as e:
        logger.warning(
            f"Failed to query stale assets from backend: {e}. "
            f"Falling back to scanning all assets."
        )
        # On error, fall back to scanning all assets
        return assets, 0


@app.task(name='src.tasks.finalize_scan', queue='discovery')
def finalize_scan(results: list, scan_id: str):
    """
    Final step: Scan finalization.
    Called after all asset scans complete.
    Marks all scanned assets with updated last_scanned_at.
    """
    logger.info(f"Scan {scan_id} completed!")

    # Calculate totals from results
    total_vulns = 0
    total_assets = len(results) if results else 0
    scanned_asset_values = []

    for result in (results or []):
        if isinstance(result, dict):
            total_vulns += result.get("vuln_count_prioritized", 0)
            total_vulns += result.get("vuln_count_full", 0)
            # Collect asset values for marking as scanned
            if result.get("value"):
                scanned_asset_values.append(result["value"])

    # Mark assets as scanned for delta scanning
    if scanned_asset_values:
        try:
            resp = post_to_backend(
                f"/scans/{scan_id}/mark-scanned",
                {"asset_values": scanned_asset_values}
            )
            resp.raise_for_status()
            logger.info(f"Marked {len(scanned_asset_values)} assets as scanned")
        except Exception as e:
            logger.warning(f"Failed to mark assets as scanned: {e}")

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
