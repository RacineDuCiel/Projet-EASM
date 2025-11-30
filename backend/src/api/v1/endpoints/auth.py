from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import timedelta
from src.db import session as database
from src import models, schemas
from src.core import security as auth

router = APIRouter(
    prefix="/auth",
    tags=["auth"],
    responses={404: {"description": "Not found"}},
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")

async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(database.get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = auth.jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = schemas.TokenData(username=username)
    except auth.JWTError:
        raise credentials_exception
    
    result = await db.execute(select(models.User).where(models.User.username == token_data.username))
    user = result.scalar_one_or_none()
    
    if user is None:
        raise credentials_exception
    return user

@router.post("/token", response_model=schemas.TokenWithUser)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(database.get_db)):
    # 1. Get user
    result = await db.execute(select(models.User).where(models.User.username == form_data.username))
    user = result.scalar_one_or_none()
    
    # 2. Verify password
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # 3. Create token
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.username, "role": user.role.value, "program_id": str(user.program_id) if user.program_id else None},
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer", "user": user}

@router.post("/users/", response_model=schemas.User)
async def create_user(user: schemas.UserCreate, db: AsyncSession = Depends(database.get_db)):
    # Check if user exists
    result = await db.execute(select(models.User).where(models.User.username == user.username))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_password = auth.get_password_hash(user.password)
    db_user = models.User(
        username=user.username, 
        hashed_password=hashed_password,
        role=user.role,
        program_id=user.program_id
    )
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user
    return db_user

@router.get("/users/", response_model=list[schemas.User])
async def read_users(
    skip: int = 0, 
    limit: int = 100, 
    current_user: models.User = Depends(get_current_user),
    db: AsyncSession = Depends(database.get_db)
):
    if current_user.role != models.UserRole.admin:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    from sqlalchemy.orm import selectinload
    result = await db.execute(
        select(models.User)
        .options(selectinload(models.User.program))
        .offset(skip)
        .limit(limit)
    )
    return result.scalars().all()
    return result.scalars().all()

@router.delete("/users/{user_id}", status_code=204)
async def delete_user(
    user_id: str,
    current_user: models.User = Depends(get_current_user),
    db: AsyncSession = Depends(database.get_db)
):
    if current_user.role != models.UserRole.admin:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Prevent self-deletion
    if str(current_user.id) == user_id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    from uuid import UUID
    try:
        user_uuid = UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user ID format")

    result = await db.execute(select(models.User).where(models.User.id == user_uuid))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    await db.delete(user)
    await db.commit()
    return
