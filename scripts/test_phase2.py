import requests
import time
import sys

BASE_URL = "http://localhost:8000"

def log(msg):
    print(f"[TEST] {msg}")

def main():
    # 1. Create Program
    log("Création du programme 'Phase 2 Test'...")
    r = requests.post(f"{BASE_URL}/programs/", json={"name": "Phase 2 Test"})
    r.raise_for_status()
    program_id = r.json()["id"]

    # 2. Create Scope
    # We use scanme.nmap.org as a safe target for active scanning
    target = "scanme.nmap.org"
    log(f"Ajout du scope '{target}'...")
    r = requests.post(f"{BASE_URL}/programs/{program_id}/scopes/", json={
        "scope_type": "domain",
        "value": target
    })
    r.raise_for_status()
    scope_id = r.json()["id"]

    # 3. Start Scan
    log("Lancement d'un scan complet (Real Tools)...")
    r = requests.post(f"{BASE_URL}/scans/", json={
        "scan_type": "full",
        "scope_id": scope_id
    })
    r.raise_for_status()
    scan_id = r.json()["id"]
    log(f"Scan démarré : ID={scan_id}")

    # 4. Poll for Completion
    log("Attente des résultats (cela peut prendre 1-2 minutes)...")
    start_time = time.time()
    while True:
        if time.time() - start_time > 300: # 5 minutes max
            log("Timeout !")
            sys.exit(1)
            
        time.sleep(5)
        r = requests.get(f"{BASE_URL}/scans/")
        scans = r.json()
        my_scan = next((s for s in scans if s["id"] == scan_id), None)
        
        if my_scan:
            status = my_scan["status"]
            log(f"Status du scan : {status}")
            if status == "completed":
                break
            if status == "failed":
                log("Le scan a échoué.")
                sys.exit(1)

    # 5. Verify Results
    log("Vérification des résultats...")
    r = requests.get(f"{BASE_URL}/assets/")
    assets = r.json()
    
    found_target = False
    for asset in assets:
        if target in asset["value"]:
            found_target = True
            log(f"Asset trouvé : {asset['value']}")
            log(f" - Services : {len(asset['services'])}")
            for svc in asset['services']:
                log(f"   - Port {svc['port']}/{svc['protocol']}")
            
            log(f" - Vulns : {len(asset['vulnerabilities'])}")
            for vuln in asset['vulnerabilities']:
                log(f"   - [{vuln['severity']}] {vuln['title']}")

    if found_target:
        log("Test Phase 2 réussi !")
    else:
        log("Cible non trouvée dans les assets.")
        sys.exit(1)

if __name__ == "__main__":
    main()
