from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from src.core.config import settings

# Convert postgresql:// to postgresql+asyncpg:// for async support
DATABASE_URL = settings.DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://")

# Disable SQL echo in production
SQL_ECHO = settings.ENVIRONMENT == "development"

# Enhanced connection pooling configuration for production
engine = create_async_engine(
    DATABASE_URL,
    echo=SQL_ECHO,
    # Connection pool settings
    pool_size=20,              # Number of persistent connections (increased from 10)
    max_overflow=10,           # Additional connections when pool is exhausted
    pool_timeout=30,           # Seconds to wait for an available connection
    pool_pre_ping=True,        # Verify connection before using (prevents stale connections)
    pool_recycle=1800,         # Recycle connections after 30 minutes (prevents stale connections)
    # Performance optimizations
    pool_use_lifo=True,        # Use LIFO for better connection reuse
)

AsyncSessionLocal = sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

Base = declarative_base()

async def get_db():
    """Dependency to get async database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
