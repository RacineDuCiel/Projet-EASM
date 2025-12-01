from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from uuid import UUID
from src import crud, schemas
from src.api.v1.endpoints import auth
from src.db import session as database

router = APIRouter(
    prefix="/programs",
    tags=["programs"],
    responses={404: {"description": "Not found"}},
)

@router.post("/", response_model=schemas.Program)
async def create_program(program: schemas.ProgramCreate, db: AsyncSession = Depends(database.get_db)):
    return await crud.create_program(db=db, program=program)

@router.get("/", response_model=List[schemas.Program])
async def read_programs(skip: int = 0, limit: int = 100, db: AsyncSession = Depends(database.get_db)):
    return await crud.get_programs(db, skip=skip, limit=limit)

@router.get("/{program_id}", response_model=schemas.Program)
async def read_program(program_id: UUID, db: AsyncSession = Depends(database.get_db)):
    db_program = await crud.get_program(db, program_id=program_id)
    if db_program is None:
        raise HTTPException(status_code=404, detail="Program not found")
    return db_program

@router.post("/{program_id}/scopes/", response_model=schemas.Scope)
async def create_scope_for_program(
    program_id: UUID, 
    scope: schemas.ScopeCreate, 
    db: AsyncSession = Depends(database.get_db),
    current_user: schemas.User = Depends(auth.get_current_user)
):
    # Check if program exists
    program = await crud.get_program(db, program_id)
    if not program:
        raise HTTPException(status_code=404, detail="Program not found")
        
    # Check permissions (optional, but good practice)
    # if current_user.role != UserRole.admin and current_user.program_id != program_id:
    #     raise HTTPException(status_code=403, detail="Not authorized to add scope to this program")

    try:
        return await crud.create_scope(db=db, scope=scope, program_id=program_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        # Log the error
        print(f"Error creating scope: {e}")
        # Expose error for debugging (remove in production)
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")

@router.get("/{program_id}/scopes/", response_model=List[schemas.Scope])
async def read_scopes(program_id: UUID, db: AsyncSession = Depends(database.get_db)):
    return await crud.get_scopes(db, program_id=program_id)

@router.delete("/{program_id}", status_code=204)
async def delete_program(program_id: UUID, db: AsyncSession = Depends(database.get_db)):
    program = await crud.delete_program(db, program_id)
    if not program:
        raise HTTPException(status_code=404, detail="Program not found")
    return

@router.delete("/{program_id}/scopes/{scope_id}", status_code=204)
async def delete_scope(program_id: UUID, scope_id: UUID, db: AsyncSession = Depends(database.get_db)):
    scope = await crud.delete_scope(db, scope_id)
    if not scope:
        raise HTTPException(status_code=404, detail="Scope not found")
    return
