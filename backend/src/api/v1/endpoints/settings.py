from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from src import crud, schemas
from src.db import session as database
from src.api.v1.endpoints import auth
from src.models import User
from src.models.enums import ScanFrequency
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
    scan_frequency: ScanFrequency | None = None
    # Automated monitoring configuration
    auto_scan_enabled: bool | None = None
    delta_scan_enabled: bool | None = None
    delta_scan_threshold_hours: int | None = None

@router.get("/", response_model=schemas.Program)
async def get_settings(
    db: AsyncSession = Depends(database.get_db),
    current_user: User = Depends(auth.get_current_user)
):
    if not current_user.program_id:
        if current_user.role == "admin":
            # Return empty/default for admin without program
            # Or raise 404 but handled gracefully?
            # Better to return 404 and let frontend handle it, 
            # BUT the user complained about the error.
            # Let's return a dummy program or handle it.
            # Actually, let's just raise 404 but with a clear detail.
            raise HTTPException(status_code=404, detail="Admin not associated with a program")
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
    
    # Allow any user associated with the program to update settings
    # if current_user.role != "admin":
    #    raise HTTPException(status_code=403, detail="Not authorized to update settings")

    program = await crud.get_program(db, current_user.program_id)
    if not program:
        raise HTTPException(status_code=404, detail="Program not found")
    
    # Update program
    if settings.discord_webhook_url is not None:
        program.discord_webhook_url = settings.discord_webhook_url
    if settings.scan_frequency is not None:
        program.scan_frequency = settings.scan_frequency
    # Automated monitoring configuration
    if settings.auto_scan_enabled is not None:
        program.auto_scan_enabled = settings.auto_scan_enabled
    if settings.delta_scan_enabled is not None:
        program.delta_scan_enabled = settings.delta_scan_enabled
    if settings.delta_scan_threshold_hours is not None:
        program.delta_scan_threshold_hours = settings.delta_scan_threshold_hours

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
            "content": "🔔 **Test Notification**\nThis is a test message from your EASM platform. If you see this, the configuration is correct"
        }
        resp = requests.post(program.discord_webhook_url, json=payload, timeout=5)
        resp.raise_for_status()
        return {"status": "ok", "message": "Notification sent"}
    except Exception as e:
        logger.error(f"Failed to send test notification: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to send notification: {str(e)}")
