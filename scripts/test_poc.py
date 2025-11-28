import requests
import time
import sys

BASE_URL = "http://localhost:8000"

def log(msg):
    print(f"[TEST] {msg}")

def main():
    # 1. Check API Status
    try:
        r = requests.get(f"{BASE_URL}/")
        if r.status_code != 200:
            log("L'API ne répond pas correctement sur /")
            sys.exit(1)
        log("API en ligne.")
    except requests.exceptions.ConnectionError:
        log("Impossible de se connecter à l'API. Avez-vous lancé 'docker-compose up' ?")
        sys.exit(1)

    # 2. Create Program
    log("Création du programme 'Demo Corp'...")
    r = requests.post(f"{BASE_URL}/programs/", json={"name": "Demo Corp"})
    r.raise_for_status()
    program = r.json()
    program_id = program["id"]
    log(f"Programme créé : ID={program_id}")

    # 3. Create Scope
    log("Ajout du scope 'example.com'...")
    r = requests.post(f"{BASE_URL}/programs/{program_id}/scopes/", json={
        "scope_type": "domain",
        "value": "example.com"
    })
    r.raise_for_status()
    scope = r.json()
    scope_id = scope["id"]
    log(f"Scope créé : ID={scope_id}")

    # 4. Start Scan
    log("Lancement d'un scan passif...")
    r = requests.post(f"{BASE_URL}/scans/", json={
        "scan_type": "passive",
        "scope_id": scope_id
    })
    r.raise_for_status()
    scan = r.json()
    scan_id = scan["id"]
    log(f"Scan démarré : ID={scan_id} (Status: {scan['status']})")

    # 5. Poll for Completion
    log("Attente des résultats (polling)...")
    for _ in range(10):  # Wait up to 10 * 2 = 20 seconds
        time.sleep(2)
        r = requests.get(f"{BASE_URL}/scans/")
        scans = r.json()
        # Find our scan
        my_scan = next((s for s in scans if s["id"] == scan_id), None)
        
        if my_scan:
            status = my_scan["status"]
            log(f"Status du scan : {status}")
            if status == "completed":
                break
            if status == "failed":
                log("Le scan a échoué.")
                sys.exit(1)
        else:
            log("Scan introuvable ?")

    # 6. Verify Assets
    log("Vérification des assets découverts...")
    r = requests.get(f"{BASE_URL}/assets/")
    r.raise_for_status()
    assets = r.json()
    log(f"Assets trouvés : {len(assets)}")
    
    if len(assets) > 0:
        for asset in assets:
            log(f" - [{asset['asset_type']}] {asset['value']}")
    else:
        log("Aucun asset trouvé ! (Le worker a-t-il bien fonctionné ?)")
        sys.exit(1)

    log("Test terminé avec succès ! (Vérifiez les logs du worker pour les détails)")

if __name__ == "__main__":
    main()
