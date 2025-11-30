import requests
import logging
import subprocess
from src.celery_app import app, BACKEND_URL
from src.utils import HTTP_TIMEOUT

logger = logging.getLogger(__name__)

@app.task(name='src.tasks.trigger_periodic_scans', queue='discovery')
def trigger_periodic_scans():
    """
    Tâche planifiée : Récupère tous les programmes et lance un scan pour chaque scope.
    """
    logger.info("Lancement des scans périodiques...")
    try:
        resp = requests.get(f"{BACKEND_URL}/programs/", timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        programs = resp.json()
        
        count = 0
        for program in programs:
            for scope in program.get("scopes", []):
                scan_payload = {
                    "scope_id": scope["id"],
                    "scan_type": "active"
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
    
    for tool in ["subfinder", "naabu", "nuclei"]:
        try:
            res = subprocess.run([tool, "-version"], capture_output=True, text=True, timeout=10)
            status["tools"][tool] = "ok" if res.returncode == 0 else "error"
        except Exception as e:
            status["tools"][tool] = f"missing: {e}"
        
    logger.info(f"Health Check Results: {status}")
    return status
