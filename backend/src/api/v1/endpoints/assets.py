from fastapi import APIRouter, Depends, HTTPException
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

from typing import Optional
from uuid import UUID

@router.get("/", response_model=List[schemas.Asset])
async def read_assets(
    skip: int = 0, 
    limit: int = 100, 
    scope_id: Optional[UUID] = None,
    db: AsyncSession = Depends(database.get_db),
    current_user: User = Depends(auth.get_current_user)
):
    if scope_id:
        # If scope_id is provided, we must verify the user has access to it
        # For now, we assume if they are in the program that owns the scope, it's fine.
        # Ideally we should check if scope belongs to user's program.
        if current_user.role != "admin":
             # TODO: Verify scope belongs to user's program
             pass
        return await crud.get_assets_by_scope(db, scope_id=scope_id, skip=skip, limit=limit)

    if current_user.role == "admin":
        return await crud.get_assets(db, skip=skip, limit=limit)
    else:
        return await crud.get_assets_by_program(db, program_id=current_user.program_id, skip=skip, limit=limit)

@router.get("/{asset_id}", response_model=schemas.Asset)
async def read_asset(
    asset_id: UUID,
    db: AsyncSession = Depends(database.get_db),
    current_user: User = Depends(auth.get_current_user)
):
    asset = await crud.get_asset(db, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    # Check permissions
    if current_user.role != "admin":
        # Check if asset belongs to user's program
        # This is a bit indirect, we check if asset -> scope -> program matches
        # Ideally we should do this in the query, but for now:
        if asset.scope.program_id != current_user.program_id:
             raise HTTPException(status_code=403, detail="Not authorized to view this asset")
             
    return asset
