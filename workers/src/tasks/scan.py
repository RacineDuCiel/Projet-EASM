import requests
import logging
import json
from src.celery_app import app, BACKEND_URL
from src import tools
from src.utils import log_event, HTTP_TIMEOUT

logger = logging.getLogger(__name__)

@app.task(
    name='src.tasks.port_scan_task',
    queue='scan',
    autoretry_for=(requests.RequestException, requests.Timeout),
    retry_kwargs={'max_retries': 2, 'countdown': 120},
    retry_backoff=True
)
def port_scan_task(asset, scan_id):
    """
    Etape 3a: Scan de ports (Naabu)
    """
    domain = asset["value"]
    logger.info(f"Port scan sur {domain}...")
    log_event(scan_id, f"Starting port scan on {domain}...")
    
    try:
        open_ports = tools.run_naabu(domain)
        asset["services"] = open_ports
        
        log_event(scan_id, f"Port scan finished on {domain}. Found {len(open_ports)} ports.")
        
        if open_ports:
            try:
                resp = requests.post(
                    f"{BACKEND_URL}/scans/{scan_id}/assets",
                    json=[asset],
                    timeout=HTTP_TIMEOUT
                )
                resp.raise_for_status()
                logger.info(f"Sent {len(open_ports)} services to backend for {domain}")
            except Exception as e:
                logger.error(f"Erreur envoi services for {domain}: {e}", exc_info=True)
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
    autoretry_for=(requests.RequestException, requests.Timeout),
    retry_kwargs={'max_retries': 2, 'countdown': 120},
    retry_backoff=True
)
def vuln_scan_task(asset, scan_id):
    """
    Etape 3b: Scan de vulnérabilités (Nuclei)
    """
    domain = asset["value"]
    services = asset.get("services", [])
    
    logger.info(f"Starting vulnerability scan for {domain} with {len(services)} services")
    log_event(scan_id, f"Starting vulnerability scan on {domain}...")
    
    try:
        targets = []
        
        if services:
            for service in services:
                port = service.get("port")
                if port:
                    service_name = service.get("service_name", "").lower()
                    if port == 443 or service_name in ["https", "ssl", "tls"]:
                        targets.append(f"https://{domain}:{port}")
                    elif port == 80:
                        targets.append(f"http://{domain}:{port}")
                    else:
                        targets.append(f"http://{domain}:{port}")
                        targets.append(f"https://{domain}:{port}")
        else:
            logger.warning(f"No ports discovered for {domain}, using default HTTP/HTTPS")
            targets.append(f"http://{domain}")
            targets.append(f"https://{domain}")
        
        targets = list(set(targets))
        
        all_vulns = []
        seen_titles = set()
        
        # Batch processing configuration
        BATCH_SIZE = 5
        current_batch = []
        
        for target_url in targets:
            # Consume the generator
            for finding in tools.run_nuclei(target_url):
                if finding["title"] not in seen_titles:
                    seen_titles.add(finding["title"])
                    current_batch.append(finding)
                    all_vulns.append(finding)
                    
                    # If batch is full, send it
                    if len(current_batch) >= BATCH_SIZE:
                        _send_vuln_batch(asset, current_batch, scan_id, domain)
                        current_batch = [] # Reset batch

        # Send remaining findings
        if current_batch:
            _send_vuln_batch(asset, current_batch, scan_id, domain)
        
        asset["vulnerabilities"] = all_vulns
        logger.info(f"Vulnerability scan completed for {domain}: {len(all_vulns)} unique vulnerabilities found")
        log_event(scan_id, f"Vuln scan finished on {domain}. Found {len(all_vulns)} vulnerabilities.")
        
        return asset
    except Exception as e:
        logger.error(f"Vuln scan failed for {domain}: {e}", exc_info=True)
        log_event(scan_id, f"Vuln scan failed on {domain}: {str(e)}", "error")
        asset["vulnerabilities"] = []
        return asset

def _send_vuln_batch(asset, vulns, scan_id, domain):
    """Helper to send a batch of vulnerabilities to the backend."""
    try:
        # Create a copy of asset with only this batch of vulnerabilities
        asset_update = asset.copy()
        asset_update["vulnerabilities"] = vulns
        
        payload = [asset_update]
        resp = requests.post(
            f"{BACKEND_URL}/scans/{scan_id}/assets",
            json=payload,
            timeout=HTTP_TIMEOUT
        )
        resp.raise_for_status()
        logger.info(f"Successfully sent batch of {len(vulns)} vulnerabilities to backend for {domain}")
    except Exception as e:
        logger.error(f"Failed to send vulnerability batch to backend for {domain}: {e}", exc_info=True)
        # We don't raise here to allow scanning to continue, but we log the error.
        # Ideally, we might want to retry or track failed batches.
