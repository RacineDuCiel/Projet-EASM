import requests
import uuid
import json

API_URL = "http://localhost:8000"
USERNAME = "admin" # Assuming admin exists or I can create one, but let's use the same logic as test script
PASSWORD = "testpassword123"

def main():
    # 1. Register/Login
    username = f"debug_{uuid.uuid4().hex[:8]}"
    requests.post(f"{API_URL}/auth/users/", json={"username": username, "password": PASSWORD})
    
    resp = requests.post(f"{API_URL}/auth/token", data={"username": username, "password": PASSWORD})
    if resp.status_code != 200:
        print(f"Login failed: {resp.text}")
        return
    
    token = resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # 2. Get Assets
    print("Fetching assets...")
    resp = requests.get(f"{API_URL}/assets/", headers=headers)
    if resp.status_code != 200:
        print(f"Failed to get assets: {resp.text}")
        return
    
    assets = resp.json()
    print(f"Found {len(assets)} assets.")
    
    for asset in assets:
        print(f"\nAsset: {asset['value']} (ID: {asset['id']})")
        print(f"  Vulnerabilities: {len(asset.get('vulnerabilities', []))}")
        print(json.dumps(asset.get('vulnerabilities', []), indent=2))

if __name__ == "__main__":
    main()
