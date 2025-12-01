from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from src import crud, schemas
from src.db import session as database
from src.api.v1.endpoints import auth
from src.models import User, UserRole

router = APIRouter()

@router.get("/", response_model=List[schemas.SystemLog])
async def read_system_logs(
    skip: int = 0, 
    limit: int = 50, 
    db: AsyncSession = Depends(database.get_db),
    current_user: User = Depends(auth.get_current_user)
):
    if current_user.role != UserRole.admin:
        raise HTTPException(status_code=403, detail="Only admins can view system logs")
    return await crud.get_system_logs(db, skip=skip, limit=limit)
