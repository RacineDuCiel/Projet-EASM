import requests
import uuid
import json
import sys

API_URL = "http://localhost:8000"
USERNAME = f"debug_user_{uuid.uuid4().hex[:8]}"
PASSWORD = "testpassword123"

def print_step(msg):
    print(f"\n[STEP] {msg}")

def print_error(msg):
    print(f"   [ERROR] {msg}")
    sys.exit(1)

def main():
    print("=== Debugging Vulnerability Ingestion (Advanced) ===")

    # 1. Register & Login
    print_step("Registering and Logging in...")
    requests.post(f"{API_URL}/auth/users/", json={"username": USERNAME, "password": PASSWORD})
    resp = requests.post(f"{API_URL}/auth/token", data={"username": USERNAME, "password": PASSWORD})
    if resp.status_code != 200:
        print_error(f"Login failed: {resp.text}")
    token = resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print(f"   [OK] Logged in as {USERNAME}")

    # 2. Create Program & Scope
    print_step("Creating Program & Scope...")
    resp = requests.post(f"{API_URL}/programs/", json={"name": "Debug Program"}, headers=headers)
    program_id = resp.json()["id"]
    
    resp = requests.post(f"{API_URL}/programs/{program_id}/scopes/", json={
        "scope_type": "hostname",
        "value": "juice-shop"
    }, headers=headers)
    scope_id = resp.json()["id"]
    print(f"   [OK] Scope created: {scope_id}")

    # 3. Create Scan
    print_step("Creating Scan...")
    resp = requests.post(f"{API_URL}/scans/", json={"scope_id": scope_id, "scan_type": "active"}, headers=headers)
    scan_id = resp.json()["id"]
    print(f"   [OK] Scan created: {scan_id}")

    # 4. Send Asset with Services AND Vulnerabilities
    print_step("Sending Asset with Services and Vulnerabilities...")
    # This payload mimics what the worker sends
    payload = [
        {
            "value": "juice-shop",
            "asset_type": "subdomain",
            "is_active": True,
            "services": [
                {
                    "port": 3000,
                    "protocol": "tcp",
                    "service_name": "unknown"
                }
            ],
            "vulnerabilities": [
                {
                    "title": "Juice Shop Info Leak",
                    "severity": "info", # Lowercase, matching Enum
                    "description": "Found something interesting.",
                    "status": "open"
                },
                {
                    "title": "Juice Shop XSS",
                    "severity": "high",
                    "description": "Cross Site Scripting detected.",
                    "status": "open"
                }
            ]
        }
    ]
    
    resp = requests.post(f"{API_URL}/scans/{scan_id}/assets", json=payload, headers=headers)
    if resp.status_code != 200:
        print_error(f"Failed to send assets: {resp.status_code} - {resp.text}")
    
    print(f"   [OK] Assets sent. Response: {resp.json()}")

    # 5. Verify Persistence
    print_step("Verifying Persistence via API...")
    resp = requests.get(f"{API_URL}/assets/", headers=headers)
    assets = resp.json()
    
    target_asset = next((a for a in assets if a["value"] == "juice-shop" and a["scope_id"] == scope_id), None)
    
    if not target_asset:
        print_error("Asset not found in GET /assets/")
        
    vulns = target_asset.get("vulnerabilities", [])
    services = target_asset.get("services", [])
    
    print(f"   [INFO] Found {len(services)} services on asset.")
    print(f"   [INFO] Found {len(vulns)} vulnerabilities on asset.")
    
    for v in vulns:
        print(f"      - {v['title']} ({v['severity']})")
        
    if len(vulns) == 2 and len(services) == 1:
        print("\n=== SUCCESS: Vulnerabilities and Services persisted correctly! ===")
    else:
        print("\n=== FAILURE: Data missing! ===")
        print(f"Expected 2 vulns, found {len(vulns)}")
        print(f"Expected 1 service, found {len(services)}")

if __name__ == "__main__":
    main()
