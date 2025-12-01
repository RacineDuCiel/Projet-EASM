import asyncio
import requests
import sys
import os

# Add backend directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.models import UserRole
from src.core.security import create_access_token
from src.db.session import async_session
from src.models import User
from sqlalchemy import select
from datetime import timedelta

API_URL = "http://localhost:8000/api/v1"

async def get_token(role: UserRole):
    async with async_session() as db:
        result = await db.execute(select(User).where(User.role == role).limit(1))
        user = result.scalar_one_or_none()
        if not user:
            print(f"No user found with role {role}")
            return None
        
        access_token = create_access_token(
            data={"sub": user.username, "role": user.role.value, "program_id": str(user.program_id) if user.program_id else None},
            expires_delta=timedelta(minutes=30)
        )
        return access_token

async def reproduce_issues():
    print("Starting reproduction script...")
    
    # 1. Authenticate as Admin
    token = await get_token(UserRole.admin)
    if not token:
        print("Cannot proceed without admin token")
        return
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # 2. Test Settings Endpoint (GET /settings/)
    print("\n--- Testing GET /settings/ ---")
    try:
        resp = requests.get(f"{API_URL}/settings/", headers=headers)
        print(f"GET /settings/ Status: {resp.status_code}")
        if resp.status_code != 200:
            print(f"Response: {resp.text}")
    except Exception as e:
        print(f"Failed to connect: {e}")

    # 3. Test Create Program
    print("\n--- Testing Create Program ---")
    program_data = {"name": "Test Program Reproduction"}
    try:
        resp = requests.post(f"{API_URL}/programs/", json=program_data, headers=headers)
        print(f"POST /programs/ Status: {resp.status_code}")
        if resp.status_code == 200:
            program_id = resp.json()["id"]
            print(f"Created Program ID: {program_id}")
            
            # 4. Test Add Scope
            print("\n--- Testing Add Scope ---")
            scope_data = {"value": "example.com", "scope_type": "domain"}
            resp = requests.post(f"{API_URL}/programs/{program_id}/scopes/", json=scope_data, headers=headers)
            print(f"POST /programs/{program_id}/scopes/ Status: {resp.status_code}")
            if resp.status_code != 200:
                print(f"Response: {resp.text}")
                
            # Cleanup
            requests.delete(f"{API_URL}/programs/{program_id}", headers=headers)
        else:
            print(f"Failed to create program: {resp.text}")
    except Exception as e:
        print(f"Failed to connect: {e}")

if __name__ == "__main__":
    asyncio.run(reproduce_issues())
