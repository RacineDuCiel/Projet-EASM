from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from uuid import UUID
from src import models, schemas

async def create_program(db: AsyncSession, program: schemas.ProgramCreate):
    db_program = models.Program(name=program.name)
    db.add(db_program)
    await db.commit()
    await db.refresh(db_program)
    return db_program

async def get_programs(db: AsyncSession, skip: int = 0, limit: int = 100):
    result = await db.execute(select(models.Program).offset(skip).limit(limit))
    return result.scalars().all()

async def get_program(db: AsyncSession, program_id: UUID):
    result = await db.execute(
        select(models.Program)
        .options(selectinload(models.Program.scopes))
        .where(models.Program.id == program_id)
    )
    return result.scalar_one_or_none()

async def create_scope(db: AsyncSession, scope: schemas.ScopeCreate, program_id: UUID):
    db_scope = models.Scope(**scope.model_dump(), program_id=program_id)
    db.add(db_scope)
    await db.commit()
    await db.refresh(db_scope)
    return db_scope

async def get_scopes(db: AsyncSession, program_id: UUID):
    result = await db.execute(select(models.Scope).where(models.Scope.program_id == program_id))
    return result.scalars().all()

async def get_scope(db: AsyncSession, scope_id: UUID):
    result = await db.execute(select(models.Scope).where(models.Scope.id == scope_id))
    return result.scalar_one_or_none()
