from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from src import crud, schemas
from src.db import session as database
from src.api.v1.endpoints import auth
from src.models import User
import requests
import logging

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/settings",
    tags=["settings"],
    responses={404: {"description": "Not found"}},
)

class SettingsUpdate(BaseModel):
    discord_webhook_url: str | None = None

@router.get("/", response_model=schemas.Program)
async def get_settings(
    db: AsyncSession = Depends(database.get_db),
    current_user: User = Depends(auth.get_current_user)
):
    if not current_user.program_id:
        raise HTTPException(status_code=404, detail="User not associated with a program")
    
    program = await crud.get_program(db, current_user.program_id)
    if not program:
        raise HTTPException(status_code=404, detail="Program not found")
    
    return program

@router.patch("/", response_model=schemas.Program)
async def update_settings(
    settings: SettingsUpdate,
    db: AsyncSession = Depends(database.get_db),
    current_user: User = Depends(auth.get_current_user)
):
    if not current_user.program_id:
        raise HTTPException(status_code=404, detail="User not associated with a program")
    
    # Only admin can update settings? For now let's say yes.
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to update settings")

    program = await crud.get_program(db, current_user.program_id)
    if not program:
        raise HTTPException(status_code=404, detail="Program not found")
    
    # Update program
    # We need to add update_program to crud if it doesn't support partial updates easily
    # Or we can just do it here for now since it's one field
    program.discord_webhook_url = settings.discord_webhook_url
    db.add(program)
    await db.commit()
    await db.refresh(program)
    
    return program

@router.post("/test-notification")
async def test_notification(
    db: AsyncSession = Depends(database.get_db),
    current_user: User = Depends(auth.get_current_user)
):
    if not current_user.program_id:
        raise HTTPException(status_code=404, detail="User not associated with a program")
        
    program = await crud.get_program(db, current_user.program_id)
    if not program or not program.discord_webhook_url:
        raise HTTPException(status_code=400, detail="Discord Webhook URL not configured")
    
    try:
        payload = {
            "content": "🔔 **Test Notification**\nThis is a test message from your EASM platform. If you see this, the configuration is correct! ✅"
        }
        resp = requests.post(program.discord_webhook_url, json=payload, timeout=5)
        resp.raise_for_status()
        return {"status": "ok", "message": "Notification sent"}
    except Exception as e:
        logger.error(f"Failed to send test notification: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to send notification: {str(e)}")
