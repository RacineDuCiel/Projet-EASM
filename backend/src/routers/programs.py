from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from uuid import UUID
from .. import crud, schemas, database

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
    program_id: UUID, scope: schemas.ScopeCreate, db: AsyncSession = Depends(database.get_db)
):
    return await crud.create_scope(db=db, scope=scope, program_id=program_id)

@router.get("/{program_id}/scopes/", response_model=List[schemas.Scope])
async def read_scopes(program_id: UUID, db: AsyncSession = Depends(database.get_db)):
    return await crud.get_scopes(db, program_id=program_id)
