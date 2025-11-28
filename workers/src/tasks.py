import time
from celery import Celery
import os
import requests
from . import tools

# Configuration Celery
app = Celery('tasks', broker=os.getenv("REDIS_URL"))

BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000")

@app.task(name='src.tasks.run_scan')
def run_scan(target, scan_id):
    """
    Exécute un scan réel (Subfinder -> Naabu -> Nuclei) et envoie les résultats.
    """
    print(f"[*] Début du scan pour : {target} (ID: {scan_id})")
    
    results = {
        "status": "running",
        "assets": []
    }
    
    # 1. Passive Discovery (Subfinder)
    subdomains = tools.run_subfinder(target)
    
    # Add target itself if not found (e.g. if target is a domain)
    if target not in subdomains:
        subdomains.append(target)
        
    for sub in subdomains:
        results["assets"].append({
            "value": sub,
            "asset_type": "subdomain",
            "is_active": True,
            "services": [],
            "vulnerabilities": []
        })
        
    # 2. Active Scanning (Naabu & Nuclei)
    # For POC, we scan all found subdomains. In prod, we'd queue separate tasks.
    for asset in results["assets"]:
        domain = asset["value"]
        
        # Port Scan
        open_ports = tools.run_naabu(domain)
        asset["services"] = open_ports
        
        # Vulnerability Scan (only if web ports are open or just try http/https)
        # Nuclei handles connection checks.
        if open_ports: # Only scan if ports are found? Or just try anyway?
            # Let's try http://domain and https://domain
            vulns = tools.run_nuclei(f"http://{domain}")
            vulns += tools.run_nuclei(f"https://{domain}")
            asset["vulnerabilities"] = vulns

    results["status"] = "completed"
    
    # Envoi des résultats au backend
    try:
        # Note: The backend expects a specific format. We might need to adjust the payload
        # or the backend endpoint to handle nested services/vulns.
        # For now, let's assume we send the whole blob and the backend handles it.
        response = requests.post(f"{BACKEND_URL}/scans/{scan_id}/results", json=results)
        response.raise_for_status()
        print(f"[*] Résultats envoyés pour {target}")
    except Exception as e:
        print(f"[!] Erreur lors de l'envoi des résultats : {e}")
        # On pourrait réessayer ou logger l'erreur
    
    return results