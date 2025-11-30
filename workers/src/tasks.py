import os
import requests
import subprocess
import logging
import json
from celery import Celery, chain, group, chord
from celery.schedules import crontab
from . import tools

# Configuration logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration Celery
app = Celery('tasks', broker=os.getenv("REDIS_URL"), backend=os.getenv("REDIS_URL"))

# Backend URL
BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000")

# HTTP Timeout (secondes)
HTTP_TIMEOUT = 30

# Configuration du Scheduling (Beat)
app.conf.beat_schedule = {
    'scan-every-night-at-2am': {
        'task': 'src.tasks.trigger_periodic_scans',
        'schedule': crontab(hour=2, minute=0), # Tous les jours à 2h00
    },
}
app.conf.timezone = 'UTC'

# Configuration Celery avancée pour robustesse
app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_reject_on_worker_lost=True,
    # Monitoring / Flower
    worker_send_task_events=True,
    task_send_sent_event=True,
    task_track_started=True,
)

def log_event(scan_id, message, severity="info"):
    """
    Helper to send scan events to the backend.
    """
    try:
        requests.post(
            f"{BACKEND_URL}/scans/{scan_id}/events",
            json={
                "message": message,
                "severity": severity
            },
            timeout=HTTP_TIMEOUT
        )
    except Exception as e:
        logger.error(f"Failed to log event: {e}")

@app.task(name='src.tasks.trigger_periodic_scans', queue='discovery')
def trigger_periodic_scans():
    """
    Tâche planifiée : Récupère tous les programmes et lance un scan pour chaque scope.
    """
    logger.info("Lancement des scans périodiques...")
    try:
        # 1. Récupérer les programmes (et leurs scopes)
        resp = requests.get(f"{BACKEND_URL}/programs/", timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        programs = resp.json()
        
        count = 0
        for program in programs:
            for scope in program.get("scopes", []):
                # 2. Créer un scan via l'API (ce qui déclenchera run_scan)
                scan_payload = {
                    "scope_id": scope["id"],
                    "scan_type": "active" # Ou "full"
                }
                try:
                    r = requests.post(f"{BACKEND_URL}/scans/", json=scan_payload, timeout=HTTP_TIMEOUT)
                    r.raise_for_status()
                    logger.info(f"Scan lancé pour {scope['value']}")
                    count += 1
                except Exception as e:
                    logger.error(f"Erreur lancement scan pour {scope['value']}: {e}")
                    
        logger.info(f"Scans périodiques terminés. {count} scans lancés.")
        
    except Exception as e:
        logger.error(f"Erreur critique periodic scans: {e}", exc_info=True)

@app.task(name='src.tasks.health_check', queue='discovery')
def health_check():
    """
    Tâche de diagnostic pour vérifier que les outils sont installés et fonctionnels.
    """
    logger.info("Running Worker Health Check...")
    status = {"status": "ok", "tools": {}}
    
    # Check Subfinder
    try:
        res = subprocess.run(["subfinder", "-version"], capture_output=True, text=True, timeout=10)
        status["tools"]["subfinder"] = "ok" if res.returncode == 0 else "error"
    except Exception as e:
        status["tools"]["subfinder"] = f"missing: {e}"

    # Check Naabu
    try:
        res = subprocess.run(["naabu", "-version"], capture_output=True, text=True, timeout=10)
        status["tools"]["naabu"] = "ok" if res.returncode == 0 else "error"
    except Exception as e:
        status["tools"]["naabu"] = f"missing: {e}"

    # Check Nuclei
    try:
        res = subprocess.run(["nuclei", "-version"], capture_output=True, text=True, timeout=10)
        status["tools"]["nuclei"] = "ok" if res.returncode == 0 else "error"
    except Exception as e:
        status["tools"]["nuclei"] = f"missing: {e}"
        
    logger.info(f"Health Check Results: {status}")
    return status

@app.task(name='src.tasks.run_scan', queue='discovery')
def run_scan(target, scan_id):
    """
    Point d'entrée principal (Legacy/Wrapper).
    Lance l'orchestration du scan.
    """
    logger.info(f"Démarrage de l'orchestration pour {target} (ID: {scan_id})")
    
    # Workflow:
    # 1. Discovery (Subfinder) -> retourne liste d'assets
    # 2. Schedule Scans (Fan-out) -> lance un group de scans par asset
    # 3. Finalize -> met à jour le statut du scan
    
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
        # 1. Run Subfinder
        subdomains = tools.run_subfinder(target)
        
        # Add target itself
        if target not in subdomains:
            subdomains.append(target)
            
        log_event(scan_id, f"Discovery completed. Found {len(subdomains)} assets.")
            
        # 2. Prepare Assets objects
        assets = []
        for sub in subdomains:
            assets.append({
                "value": sub,
                "asset_type": "subdomain",
                "is_active": True
            })
            
        # 3. Send to Backend (Incremental)
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
            raise  # Re-raise pour déclencher le retry
            
        return assets
    except Exception as e:
        logger.error(f"Discovery failed for {target}: {e}", exc_info=True)
        log_event(scan_id, f"Discovery failed: {str(e)}", "error")
        raise

@app.task(name='src.tasks.schedule_asset_scans', queue='discovery')
def schedule_asset_scans(assets, scan_id):
    """
    Etape 2: Planification dynamique des scans par asset.
    Utilise un Chord pour exécuter le callback de fin une fois TOUS les assets scannés.
    """
    logger.info(f"Planification des scans pour {len(assets)} assets...")
    log_event(scan_id, f"Scheduling scans for {len(assets)} assets.")
    
    if not assets:
        # Rien trouvé, on finit tout de suite
        logger.warning(f"No assets found for scan {scan_id}, finalizing immediately")
        finalize_scan.delay([], scan_id)
        return
    
    # Créer un header de tâches (une par asset)
    # Chaque tâche est une chaine: Port Scan -> Vuln Scan
    tasks_group = []
    
    for asset in assets:
        # On passe l'asset complet ou juste la value. Ici on passe le dict.
        # Chain: port_scan -> vuln_scan
        asset_pipeline = chain(
            port_scan_task.s(asset, scan_id),
            vuln_scan_task.s(scan_id)
        )
        tasks_group.append(asset_pipeline)
        
    # Lancer le groupe avec un callback de fin (Chord)
    callback = finalize_scan.s(scan_id)
    chord(group(tasks_group))(callback)

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
        
        # Update asset dict with services
        asset["services"] = open_ports
        
        log_event(scan_id, f"Port scan finished on {domain}. Found {len(open_ports)} ports.")
        
        # Send update to backend (Services only)
        # On renvoie l'asset complet, le backend fera le merge
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
                raise  # Re-raise pour retry
                
        return asset
    except Exception as e:
        logger.error(f"Port scan failed for {domain}: {e}", exc_info=True)
        log_event(scan_id, f"Port scan failed on {domain}: {str(e)}", "error")
        # Ne pas raise ici, on continue avec le vuln scan même sans ports
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
        # Build targets based on discovered ports
        targets = []
        
        if services:
            # If ports were discovered, scan ONLY those ports
            for service in services:
                port = service.get("port")
                if port:
                    # Smart protocol detection
                    service_name = service.get("service_name", "").lower()
                    if port == 443 or service_name in ["https", "ssl", "tls"]:
                        targets.append(f"https://{domain}:{port}")
                    elif port == 80:
                        targets.append(f"http://{domain}:{port}")
                    else:
                        # Try both protocols for non-standard ports
                        targets.append(f"http://{domain}:{port}")
                        targets.append(f"https://{domain}:{port}")
        else:
            # Fallback: No ports discovered, try default HTTP/HTTPS
            logger.warning(f"No ports discovered for {domain}, using default HTTP/HTTPS")
            targets.append(f"http://{domain}")
            targets.append(f"https://{domain}")
        
        # Deduplicate targets
        targets = list(set(targets))
        logger.info(f"Generated {len(targets)} scan targets for {domain}: {targets}")
        
        # Run Nuclei on each target
        vulns = []
        for target_url in targets:
            target_vulns = tools.run_nuclei(target_url)
            vulns.extend(target_vulns)
        
        # Deduplicate vulnerabilities by title
        unique_vulns = []
        seen_titles = set()
        for v in vulns:
            if v["title"] not in seen_titles:
                unique_vulns.append(v)
                seen_titles.add(v["title"])
        
        asset["vulnerabilities"] = unique_vulns
        logger.info(f"Vulnerability scan completed for {domain}: {len(unique_vulns)} unique vulnerabilities found")
        log_event(scan_id, f"Vuln scan finished on {domain}. Found {len(unique_vulns)} vulnerabilities.")
        
        if unique_vulns:
            try:
                # Log payload for debugging
                import json
                payload = [asset]
                logger.info(f"Sending payload to backend: {json.dumps(payload, default=str)}")

                resp = requests.post(
                    f"{BACKEND_URL}/scans/{scan_id}/assets",
                    json=payload,
                    timeout=HTTP_TIMEOUT
                )
                resp.raise_for_status()
                logger.info(f"Successfully sent {len(unique_vulns)} vulnerabilities to backend for {domain}")
            except Exception as e:
                logger.error(f"Failed to send vulnerabilities to backend for {domain}: {e}", exc_info=True)
                raise  # Re-raise pour retry
        
        return asset
    except Exception as e:
        logger.error(f"Vuln scan failed for {domain}: {e}", exc_info=True)
        log_event(scan_id, f"Vuln scan failed on {domain}: {str(e)}", "error")
        asset["vulnerabilities"] = []
        return asset

@app.task(name='src.tasks.finalize_scan', queue='discovery')
def finalize_scan(results, scan_id):
    """
    Etape 4: Finalisation du scan
    """
    logger.info(f"Scan {scan_id} terminé !")
    
    payload = {
        "status": "completed",
        "assets": [] # On a déjà tout envoyé au fil de l'eau
    }
    
    try:
        # On utilise l'endpoint original qui met à jour le statut
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