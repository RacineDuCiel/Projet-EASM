from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from src import crud, schemas
from src.db import session as database

router = APIRouter(
    prefix="/assets",
    tags=["assets"],
    responses={404: {"description": "Not found"}},
)

from src.api.v1.endpoints import auth
from src.models import User

@router.get("/", response_model=List[schemas.Asset])
async def read_assets(
    skip: int = 0, 
    limit: int = 100, 
    db: AsyncSession = Depends(database.get_db),
    current_user: User = Depends(auth.get_current_user)
):
    if current_user.role == "admin":
        return await crud.get_assets(db, skip=skip, limit=limit)
    else:
        # Filter by program's scopes
        # This requires crud.get_assets to support filtering or we do it here.
        # Better to add filtering to crud.get_assets or create get_assets_by_program
        return await crud.get_assets_by_program(db, program_id=current_user.program_id, skip=skip, limit=limit)
