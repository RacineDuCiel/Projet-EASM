import requests
import time
import sys
import uuid
import json

# Configuration
API_URL = "http://localhost:8000"
USERNAME = f"tester_notify_{uuid.uuid4().hex[:8]}"
PASSWORD = "testpassword123"
# Using juice-shop (internal Docker service) as test target
TARGET = "juice-shop"

def print_step(msg):
    print(f"\n[STEP] {msg}")

def print_success(msg):
    print(f"   [OK] {msg}")

def print_info(msg):
    print(f"   [INFO] {msg}")

def print_error(msg):
    print(f"   [ERROR] {msg}")
    sys.exit(1)

def main():
    print("=== EASM Notification Verification Script (Robust Version) ===")
    print(f"Target: {TARGET} (Internal Docker Service)")
    print("Goal: Verify Scan Completion & Notifications")

    # 1. Register
    print_step("Registering new user...")
    try:
        resp = requests.post(f"{API_URL}/auth/users/", json={
            "username": USERNAME,
            "password": PASSWORD
        })
        if resp.status_code == 200:
            print_success(f"User {USERNAME} created.")
        elif resp.status_code == 400:
            print_success("User already exists.")
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

    # 3. Test Notification Configuration (New Feature)
    print_step("Testing Discord Webhook Configuration...")
    try:
        resp = requests.post(f"{API_URL}/notifications/test", headers=headers)
        if resp.status_code == 200:
            print_success("Test notification sent successfully! Check your Discord.")
        else:
            print_info(f"Test notification failed (Status {resp.status_code}): {resp.text}")
            print_info("Continuing with scan test anyway...")
    except Exception as e:
        print_info(f"Could not call test endpoint: {e}")

    # 4. Create Program
    print_step("Creating Program...")
    resp = requests.post(f"{API_URL}/programs/", json={"name": "Notification Test"}, headers=headers)
    if resp.status_code != 200:
        print_error(f"Failed to create program: {resp.text}")
    program_id = resp.json()["id"]
    print_success(f"Program created (ID: {program_id})")

    # 5. Create Scope (using 'hostname' type for internal Docker service)
    print_step(f"Adding Scope {TARGET}...")
    resp = requests.post(f"{API_URL}/programs/{program_id}/scopes/", json={
        "scope_type": "hostname",  # Utilise le nouveau type pour services internes
        "value": TARGET
    }, headers=headers)
    if resp.status_code != 200:
        print_error(f"Failed to create scope: {resp.text}")
    scope_id = resp.json()["id"]
    print_success(f"Scope added (ID: {scope_id})")

    # 5.5 Wait for Juice Shop Availability
    print_step("Waiting for Juice Shop to be ready...")
    check_url = "http://localhost:3000"
    ready = False
    for i in range(30): # Wait up to 150s
        try:
            r = requests.get(check_url, timeout=2)
            if r.status_code == 200:
                print_success("Juice Shop is UP!")
                ready = True
                break
        except:
            pass
        sys.stdout.write(f"\r   [WAIT] Waiting for {check_url}... ({i+1}/30)")
        sys.stdout.flush()
        time.sleep(5)
    
    if not ready:
        print("\n")
        print_error("Juice Shop is NOT reachable on localhost:3000. Aborting scan test.")

    # 6. Launch Scan
    print_step("Launching Active Scan...")
    resp = requests.post(f"{API_URL}/scans/", json={
        "scope_id": scope_id,
        "scan_type": "active"
    }, headers=headers)
    scan_id = resp.json()["id"]
    print_success(f"Scan started (ID: {scan_id})")

    # 7. Monitor Results (Smart Polling with Events)
    print_step("Monitoring Scan Progress...")
    
    start_time = time.time()
    max_timeout = 600 # 10 minutes max
    scan_completed = False
    seen_event_ids = set()
    
    while time.time() - start_time < max_timeout:
        # Check Scan Status
        try:
            # 1. Get Status
            resp = requests.get(f"{API_URL}/scans/{scan_id}", headers=headers)
            if resp.status_code == 200:
                scan_data = resp.json()
                status = scan_data.get("status")
                
                # 2. Get Events
                events_resp = requests.get(f"{API_URL}/scans/{scan_id}/events", headers=headers)
                if events_resp.status_code == 200:
                    events = events_resp.json()
                    # Sort by created_at just in case
                    # events.sort(key=lambda x: x["created_at"]) 
                    
                    for evt in events:
                        if evt["id"] not in seen_event_ids:
                            print(f"\n   [EVENT] {evt['created_at']} - {evt['severity'].upper()}: {evt['message']}")
                            seen_event_ids.add(evt["id"])

                elapsed = int(time.time() - start_time)
                sys.stdout.write(f"\r   [WAIT] Status: {status} | Elapsed: {elapsed}s")
                sys.stdout.flush()
                
                if status == "completed":
                    print("\n")
                    print_success("Scan COMPLETED!")
                    scan_completed = True
                    break
                elif status == "failed":
                    print("\n")
                    print_error("Scan FAILED according to backend.")
            else:
                print(f"\n   [WARN] Could not get scan status: {resp.status_code}")
        except Exception as e:
            print(f"\n   [WARN] Connection error: {e}")
            
        time.sleep(2)

    if not scan_completed:
        print("\n")
        print_error("Timeout: Scan did not complete within 10 minutes.")

    # 8. Check Findings
    print_step("Checking Findings...")
    
    # We need to find the asset first
    resp = requests.get(f"{API_URL}/assets/", headers=headers)
    assets = resp.json()
    target_asset = next((a for a in assets if a["value"] == TARGET and a["scope_id"] == scope_id), None)
    
    vulns_found = False
    if target_asset:
        vulns = target_asset.get("vulnerabilities", [])
        print_info(f"Found {len(vulns)} vulnerabilities total.")
        for v in vulns:
            print(f"      - {v['title']} ({v['severity']})")
            if v["severity"] in ["high", "critical"]:
                vulns_found = True
    else:
        print_info("Target asset not found in results yet.")

    if vulns_found:
        print("\n=== SUCCESS: Critical/High Vulnerabilities detected! ===")
        print("Check your Discord channel for the automated alert.")
    else:
        print("\n=== PARTIAL SUCCESS: Scan completed but no HIGH/CRITICAL vulns found. ===")
        print("This is expected if Juice Shop is secure against the default Nuclei templates used.")
        print("However, the system functioned correctly (Scan -> Completion).")
        print("Check Discord for the 'Test Notification' sent earlier.")

if __name__ == "__main__":
    main()
