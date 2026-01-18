import secrets
from fastapi import APIRouter, Depends, HTTPException, status, Header
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from datetime import timedelta
from typing import Optional
from src.db import session as database
from src import models, schemas, crud
from src.core import security as auth
from src.core.config import settings

router = APIRouter(
    prefix="/auth",
    tags=["auth"],
    responses={404: {"description": "Not found"}},
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")


async def verify_worker_token(
    x_worker_token: Optional[str] = Header(None, alias="X-Worker-Token")
) -> bool:
    """
    Verify that the request comes from an authorized worker.
    Workers must send the X-Worker-Token header with the secret token.

    Raises HTTPException 401 if token is missing or invalid.
    """
    if not x_worker_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-Worker-Token header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Use timing-safe comparison to prevent timing attacks
    if not secrets.compare_digest(x_worker_token, settings.WORKER_SECRET_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid worker token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return True

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
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Account inactive. Please contact your administrator.")
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
    
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Account inactive. Please contact your administrator.")
    
    # 3. Create token
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.username, "role": user.role.value, "program_id": str(user.program_id) if user.program_id else None},
        expires_delta=access_token_expires
    )
    
    # 4. Log login event
    await crud.create_system_log(db, schemas.SystemLogCreate(
        level="info",
        message=f"User '{user.username}' logged in",
        source="auth",
        user_id=user.id
    ))

    return {"access_token": access_token, "token_type": "bearer", "user": user}

@router.post("/users/", response_model=schemas.User)
async def create_user(
    user: schemas.UserCreate, 
    current_user: models.User = Depends(get_current_user),
    db: AsyncSession = Depends(database.get_db)
):
    if current_user.role != models.UserRole.admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Secure Admin Creation
    if user.role == models.UserRole.admin:
        if not user.current_password:
             raise HTTPException(status_code=400, detail="Current password required to create an administrator")
        if not auth.verify_password(user.current_password, current_user.hashed_password):
             raise HTTPException(status_code=401, detail="Invalid current password")
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
    
    await crud.create_system_log(db, schemas.SystemLogCreate(
        level="info",
        message=f"User '{db_user.username}' created",
        source="auth",
        user_id=None # System event or admin?
    ))
    
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

@router.put("/users/{user_id}", response_model=schemas.User)
async def update_user(
    user_id: str,
    user_in: schemas.UserUpdate,
    current_user: models.User = Depends(get_current_user),
    db: AsyncSession = Depends(database.get_db)
):
    if current_user.role != models.UserRole.admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    from uuid import UUID
    try:
        user_uuid = UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user ID format")

    result = await db.execute(select(models.User).where(models.User.id == user_uuid))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Check for Last Admin Standing if deactivating or demoting
    is_demoting = user_in.role is not None and user_in.role != models.UserRole.admin
    is_deactivating = user_in.is_active is not None and user_in.is_active is False
    
    if (is_demoting or is_deactivating) and user.role == models.UserRole.admin and user.is_active:
        # Count active admins
        active_admins_count = await db.scalar(
            select(func.count(models.User.id)).where(
                models.User.role == models.UserRole.admin,
                models.User.is_active == True
            )
        )
        if active_admins_count <= 1:
            raise HTTPException(status_code=400, detail="Cannot deactivate or demote the last active administrator.")

    # Update fields
    if user_in.username is not None:
        # Check uniqueness if changing username
        if user_in.username != user.username:
            existing = await db.execute(select(models.User).where(models.User.username == user_in.username))
            if existing.scalar_one_or_none():
                raise HTTPException(status_code=400, detail="Username already taken")
        user.username = user_in.username
        
    if user_in.password is not None:
        user.hashed_password = auth.get_password_hash(user_in.password)
        
    if user_in.role is not None:
        user.role = user_in.role
        
    if user_in.program_id is not None:
        user.program_id = user_in.program_id
    elif user_in.role == models.UserRole.admin:
        # Admins don't need a program
        user.program_id = None
        
    if user_in.is_active is not None:
        user.is_active = user_in.is_active

    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user

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
        
    # Check for Last Admin Standing
    if user.role == models.UserRole.admin and user.is_active:
        active_admins_count = await db.scalar(
            select(func.count(models.User.id)).where(
                models.User.role == models.UserRole.admin,
                models.User.is_active == True
            )
        )
        if active_admins_count <= 1:
            raise HTTPException(status_code=400, detail="Cannot delete the last active administrator.")
            
    await db.delete(user)
    await db.commit()
    return
