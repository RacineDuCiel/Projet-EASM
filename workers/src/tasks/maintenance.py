import logging
import subprocess
from src.celery_app import app
from src.utils import get_from_backend, post_to_backend, HTTP_TIMEOUT

logger = logging.getLogger(__name__)

ALL_TOOLS = [
    "subfinder",
    "naabu",
    "nuclei",
    "httpx",
    "dnsx",
    "amass",
    "findomain",
    "assetfinder",
    "katana",
    "gau",
    "waybackurls",
    "tlsx",
]

TOOL_TIMEOUTS = {
    "subfinder": 30,
    "naabu": 30,
    "nuclei": 30,
    "httpx": 15,
    "dnsx": 15,
    "amass": 30,
    "findomain": 15,
    "assetfinder": 15,
    "katana": 30,
    "gau": 30,
    "waybackurls": 15,
    "tlsx": 15,
}


@app.task(name='src.tasks.trigger_periodic_scans', queue='discovery')
def trigger_periodic_scans():
    """
    Tâche planifiée : Récupère tous les programmes et lance un scan pour chaque scope.
    Uses authenticated API calls via utils.
    """
    logger.info("Lancement des scans périodiques...")
    try:
        resp = get_from_backend("/programs/", timeout=HTTP_TIMEOUT)
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
                    r = post_to_backend("/scans/", scan_payload, timeout=HTTP_TIMEOUT)
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
    Tâche de diagnostic pour vérifier que tous les outils sont installés et fonctionnels.
    Vérifie chaque outil avec --version et retourne l'état.
    """
    logger.info("Running Worker Health Check...")
    status = {"status": "ok", "tools": {}, "missing_tools": [], "error_tools": []}

    critical_tools = ["subfinder", "naabu", "nuclei"]

    for tool in ALL_TOOLS:
        try:
            timeout = TOOL_TIMEOUTS.get(tool, 10)
            res = subprocess.run([tool, "-version"], capture_output=True, text=True, timeout=timeout)

            if res.returncode == 0:
                version = res.stdout.strip() or res.stderr.strip() or "unknown"
                status["tools"][tool] = {"status": "ok", "version": version[:50]}
            else:
                error_msg = res.stderr.strip() or res.stdout.strip() or "Unknown error"
                status["tools"][tool] = {"status": "error", "error": error_msg}
                status["error_tools"].append(tool)

        except FileNotFoundError:
            status["tools"][tool] = {"status": "missing", "error": "Tool not found in PATH"}
            status["missing_tools"].append(tool)
        except subprocess.TimeoutExpired:
            status["tools"][tool] = {"status": "error", "error": "Timeout during version check"}
            status["error_tools"].append(tool)
        except Exception as e:
            status["tools"][tool] = {"status": "error", "error": str(e)}
            status["error_tools"].append(tool)

    if status["missing_tools"]:
        status["status"] = "degraded"
        logger.warning(f"Missing tools: {status['missing_tools']}")

    if status["error_tools"]:
        status["status"] = "degraded"
        logger.warning(f"Error tools: {status['error_tools']}")

    if status["missing_tools"] and any(t in critical_tools for t in status["missing_tools"]):
        status["status"] = "critical"
        logger.error("Critical tools are missing!")

    logger.info(f"Health Check Results: {status['status']}, checked {len(ALL_TOOLS)} tools")
    return status
