from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from src import models, schemas
from src.core import security
from src.core.config import settings
import logging

logger = logging.getLogger(__name__)

async def init_db(db: AsyncSession) -> None:
    result = await db.execute(select(models.User))
    user = result.first()
    
    if not user:
        logger.info("Creating first superuser")
        user_in = schemas.UserCreate(
            username=settings.FIRST_SUPERUSER,
            password=settings.FIRST_SUPERUSER_PASSWORD,
            role=models.UserRole.admin,
        )
        user = models.User(
            username=user_in.username,
            hashed_password=security.get_password_hash(user_in.password),
            role=user_in.role,
            is_active=True,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
        logger.info(f"First superuser created: {user.username}")
    else:
        logger.info("Users already exist, skipping superuser creation")
