"""
Scan tasks for port scanning and vulnerability detection.
Implémente le streaming temps réel des vulnérabilités.
"""
import logging
from typing import List, Dict, Any, Set
from src.celery_app import app
from src import tools
from src.utils import log_event, post_to_backend, HTTP_TIMEOUT

logger = logging.getLogger(__name__)

# Désactivé: on envoie maintenant immédiatement chaque vulnérabilité
# VULN_BATCH_SIZE = 5


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
    STREAMING EN TEMPS RÉEL: Chaque vulnérabilité est envoyée immédiatement au backend.
    """
    domain = asset["value"]
    services = asset.get("services", [])
    
    logger.info(f"Starting vulnerability scan for {domain} with {len(services)} services")
    log_event(scan_id, f"Starting vulnerability scan on {domain}...")
    
    try:
        targets = _build_target_urls(domain, services)
        vuln_count = 0
        seen_titles: Set[str] = set()
        
        for target_url in targets:
            for finding in tools.run_nuclei(target_url):
                # Deduplication locale
                if finding["title"] in seen_titles:
                    continue
                    
                seen_titles.add(finding["title"])
                vuln_count += 1
                
                # STREAMING IMMÉDIAT: Envoyer chaque vulnérabilité dès sa découverte
                _stream_vulnerability(domain, finding, scan_id)
        
        logger.info(f"Vulnerability scan completed for {domain}: {vuln_count} unique vulnerabilities")
        log_event(scan_id, f"Vuln scan finished on {domain}. Found {vuln_count} vulnerabilities.")
        
        # Ne pas stocker dans asset, car déjà en DB via streaming
        asset["vulnerabilities"] = []
        return asset
        
    except Exception as e:
        logger.error(f"Vuln scan failed for {domain}: {e}", exc_info=True)
        log_event(scan_id, f"Vuln scan failed on {domain}: {str(e)}", "error")
        asset["vulnerabilities"] = []
        return asset


def _stream_vulnerability(domain: str, finding: Dict, scan_id: str) -> None:
    """
    Envoie immédiatement une vulnérabilité au backend via le endpoint de streaming.
    Permet l'affichage instantané dans le Dashboard.
    """
    try:
        # Parser le port depuis l'URL si disponible
        port = None
        if ":" in finding.get("matched", ""):
            try:
                port_str = finding["matched"].split(":")[-1].split("/")[0]
                port = int(port_str)
            except (ValueError, IndexError):
                pass
        
        payload = {
            "asset_value": domain,
            "asset_type": "subdomain",  # Type par défaut, peut être amélioré
            "title": finding["title"],
            "severity": finding["severity"],
            "description": finding.get("description", ""),
            "port": port,
            "service_name": finding.get("service_name")
        }
        
        resp = post_to_backend(f"/scans/{scan_id}/vulnerabilities", payload)
        resp.raise_for_status()
        logger.info(f"Streamed vulnerability: {finding['title']} on {domain}")
        
    except Exception as e:
        logger.error(f"Failed to stream vulnerability {finding.get('title', 'Unknown')}: {e}")
        # Continue scanning, ne pas lever d'exception


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
