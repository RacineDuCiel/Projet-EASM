from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from src.core.config import settings

# Convert postgresql:// to postgresql+asyncpg:// for async support
DATABASE_URL = settings.DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://")

# Disable SQL echo in production
SQL_ECHO = settings.ENVIRONMENT == "development"

engine = create_async_engine(
    DATABASE_URL,
    echo=SQL_ECHO,
    pool_size=10,          # Number of connections to keep open
    max_overflow=20,       # Additional connections when pool is exhausted
    pool_timeout=30,       # Seconds to wait for an available connection
    pool_pre_ping=True,    # Verify connection before using
    pool_recycle=1800,     # Recycle connections after 30 minutes
)

AsyncSessionLocal = sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

Base = declarative_base()

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
