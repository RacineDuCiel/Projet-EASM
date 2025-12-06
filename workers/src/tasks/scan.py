"""
Scan tasks for port scanning and vulnerability detection.
"""
import logging
from typing import List, Dict, Any, Set
from src.celery_app import app
from src import tools
from src.utils import log_event, post_to_backend, HTTP_TIMEOUT

logger = logging.getLogger(__name__)

# Batch size for sending vulnerabilities to backend
VULN_BATCH_SIZE = 5


@app.task(
    name='src.tasks.port_scan_task',
    queue='scan',
    autoretry_for=(Exception,),
    retry_kwargs={'max_retries': 2, 'countdown': 120},
    retry_backoff=True
)
def port_scan_task(asset: Dict[str, Any], scan_id: str) -> Dict[str, Any]:
    """
    Step 3a: Port scanning with Naabu
    """
    domain = asset["value"]
    logger.info(f"Running port scan on {domain}...")
    log_event(scan_id, f"Starting port scan on {domain}...")
    
    try:
        open_ports = tools.run_naabu(domain)
        asset["services"] = open_ports
        
        log_event(scan_id, f"Port scan finished on {domain}. Found {len(open_ports)} ports.")
        
        if open_ports:
            try:
                resp = post_to_backend(f"/scans/{scan_id}/assets", [asset])
                resp.raise_for_status()
                logger.info(f"Sent {len(open_ports)} services to backend for {domain}")
            except Exception as e:
                logger.error(f"Error sending services for {domain}: {e}", exc_info=True)
                raise
                
        return asset
    except Exception as e:
        logger.error(f"Port scan failed for {domain}: {e}", exc_info=True)
        log_event(scan_id, f"Port scan failed on {domain}: {str(e)}", "error")
        asset["services"] = []
        return asset


@app.task(
    name='src.tasks.vuln_scan_task',
    queue='scan',
    autoretry_for=(Exception,),
    retry_kwargs={'max_retries': 2, 'countdown': 120},
    retry_backoff=True
)
def vuln_scan_task(asset: Dict[str, Any], scan_id: str) -> Dict[str, Any]:
    """
    Step 3b: Vulnerability scanning with Nuclei
    """
    domain = asset["value"]
    services = asset.get("services", [])
    
    logger.info(f"Starting vulnerability scan for {domain} with {len(services)} services")
    log_event(scan_id, f"Starting vulnerability scan on {domain}...")
    
    try:
        targets = _build_target_urls(domain, services)
        all_vulns, seen_titles = [], set()
        current_batch: List[Dict] = []
        
        for target_url in targets:
            for finding in tools.run_nuclei(target_url):
                if finding["title"] not in seen_titles:
                    seen_titles.add(finding["title"])
                    current_batch.append(finding)
                    all_vulns.append(finding)
                    
                    # Send batch when full
                    if len(current_batch) >= VULN_BATCH_SIZE:
                        _send_vuln_batch(asset, current_batch, scan_id, domain)
                        current_batch = []

        # Send remaining findings
        if current_batch:
            _send_vuln_batch(asset, current_batch, scan_id, domain)
        
        asset["vulnerabilities"] = all_vulns
        logger.info(f"Vulnerability scan completed for {domain}: {len(all_vulns)} unique vulnerabilities")
        log_event(scan_id, f"Vuln scan finished on {domain}. Found {len(all_vulns)} vulnerabilities.")
        
        return asset
    except Exception as e:
        logger.error(f"Vuln scan failed for {domain}: {e}", exc_info=True)
        log_event(scan_id, f"Vuln scan failed on {domain}: {str(e)}", "error")
        asset["vulnerabilities"] = []
        return asset


def _build_target_urls(domain: str, services: List[Dict]) -> List[str]:
    """Build list of target URLs from domain and discovered services."""
    targets: Set[str] = set()
    
    if services:
        for service in services:
            port = service.get("port")
            if not port:
                continue
                
            service_name = service.get("service_name", "").lower()
            
            if port == 443 or service_name in ["https", "ssl", "tls"]:
                targets.add(f"https://{domain}:{port}")
            elif port == 80:
                targets.add(f"http://{domain}:{port}")
            else:
                targets.add(f"http://{domain}:{port}")
                targets.add(f"https://{domain}:{port}")
    else:
        logger.warning(f"No ports discovered for {domain}, using default HTTP/HTTPS")
        targets.add(f"http://{domain}")
        targets.add(f"https://{domain}")
    
    return list(targets)


def _send_vuln_batch(asset: Dict, vulns: List[Dict], scan_id: str, domain: str) -> None:
    """Send a batch of vulnerabilities to the backend using pooled connection."""
    try:
        asset_update = asset.copy()
        asset_update["vulnerabilities"] = vulns
        
        resp = post_to_backend(f"/scans/{scan_id}/assets", [asset_update])
        resp.raise_for_status()
        logger.info(f"Sent batch of {len(vulns)} vulnerabilities for {domain}")
    except Exception as e:
        logger.error(f"Failed to send vulnerability batch for {domain}: {e}", exc_info=True)
        # Continue scanning, don't raise
