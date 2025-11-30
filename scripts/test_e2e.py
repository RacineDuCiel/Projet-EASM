import requests
import time
import sys
import uuid

# Configuration
API_URL = "http://localhost:8000"
USERNAME = f"tester_{uuid.uuid4().hex[:8]}" # Unique username
PASSWORD = "testpassword123"
TARGET = "scanme.nmap.org"

def print_step(msg):
    print(f"\n[STEP] {msg}")

def print_success(msg):
    print(f"   [OK] {msg}")

def print_error(msg):
    print(f"   [ERROR] {msg}")
    sys.exit(1)

def main():
    print("=== EASM End-to-End Verification Script ===")
    print(f"Target: {TARGET}")
    print(f"API: {API_URL}")

    # 1. Register
    print_step("Registering new user...")
    try:
        resp = requests.post(f"{API_URL}/auth/users/", json={
            "username": USERNAME,
            "password": PASSWORD
        })
        if resp.status_code == 200:
            print_success(f"User {USERNAME} created.")
        elif resp.status_code == 400 and "already registered" in resp.text:
            print_success(f"User {USERNAME} already exists (that's fine).")
        else:
            print_error(f"Registration failed: {resp.text}")
    except Exception as e:
        print_error(f"Could not connect to API: {e}")

    # 2. Login
    print_step("Logging in...")
    resp = requests.post(f"{API_URL}/auth/token", data={
        "username": USERNAME,
        "password": PASSWORD
    })
    if resp.status_code != 200:
        print_error(f"Login failed: {resp.text}")
    
    token = resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print_success("Token acquired.")

    # 3. Create Program
    print_step("Creating Program...")
    resp = requests.post(f"{API_URL}/programs/", json={"name": "E2E Test Program"}, headers=headers)
    if resp.status_code != 200:
        print_error(f"Create program failed: {resp.text}")
    program_id = resp.json()["id"]
    print_success(f"Program created (ID: {program_id})")

    # 4. Create Scope
    print_step(f"Adding Scope {TARGET}...")
    resp = requests.post(f"{API_URL}/programs/{program_id}/scopes/", json={
        "scope_type": "domain",
        "value": TARGET
    }, headers=headers)
    if resp.status_code != 200:
        print_error(f"Create scope failed: {resp.text}")
    scope_id = resp.json()["id"]
    print_success(f"Scope added (ID: {scope_id})")

    # 5. Launch Scan
    print_step("Launching Active Scan...")
    resp = requests.post(f"{API_URL}/scans/", json={
        "scope_id": scope_id,
        "scan_type": "active"
    }, headers=headers)
    if resp.status_code != 200:
        print_error(f"Launch scan failed: {resp.text}")
    scan_id = resp.json()["id"]
    print_success(f"Scan started (ID: {scan_id})")

    # 6. Monitor Results
    print_step("Waiting for results (timeout 60s)...")
    start_time = time.time()
    assets_found = False
    services_found = False
    
    while time.time() - start_time < 60:
        # Check Scan Status
        resp = requests.get(f"{API_URL}/scans/", headers=headers)
        scans = resp.json()
        my_scan = next((s for s in scans if s["id"] == scan_id), None)
        
        status = my_scan["status"]
        print(f"   ... Scan Status: {status}")
        
        # Check Assets
        resp = requests.get(f"{API_URL}/assets/", headers=headers) # Note: Need to implement GET /assets/ or filter by scope
        # For now, let's assume we can list all assets or filter manually if the endpoint returns all
        # Actually, crud.get_assets exists but router might not expose it fully filtered.
        # Let's try to get assets via the scope relationship if possible, or just list all.
        # Checking router... assets router has read_assets.
        
        assets = resp.json()
        target_asset = next((a for a in assets if a["value"] == TARGET), None)
        
        if target_asset:
            assets_found = True
            if target_asset.get("services") and len(target_asset["services"]) > 0:
                services_found = True
                print_success(f"Services found: {[s['port'] for s in target_asset['services']]}")
                break
        
        if status in ["completed", "failed"]:
            break
            
        time.sleep(5)

    if assets_found:
        print_success(f"Asset {TARGET} discovered.")
    else:
        print_error("Asset not found after timeout.")

    if services_found:
        print_success("Port scan successful (services detected).")
    else:
        print_error("No services detected (Naabu might have failed or been blocked).")

    print("\n=== TEST PASSED ===")

if __name__ == "__main__":
    main()
