from fastapi import FastAPI, Request
from contextlib import asynccontextmanager
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from src.db.session import engine, Base
from src.api.v1.endpoints import programs, scans, assets, monitoring, auth, notifications
from src.core.config import settings

# Rate limiter configuration
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["100/hour"] if settings.ENVIRONMENT == "production" else ["1000/hour"]
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    # Shutdown: Close connection (optional, engine handles it)

app = FastAPI(
    title="EASM Platform API",
    lifespan=lifespan,
    description="External Attack Surface Management Platform",
    version="1.0.0"
)

# Add rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.include_router(auth.router, prefix="/api/v1")
app.include_router(programs.router, prefix="/api/v1")
app.include_router(scans.router, prefix="/api/v1")
app.include_router(assets.router, prefix="/api/v1")
app.include_router(monitoring.router, prefix="/api/v1")
app.include_router(notifications.router, prefix="/api/v1")

@app.get("/")
def read_root():
    return {
        "status": "EASM API is running",
        "environment": settings.ENVIRONMENT,
        "docs": "/docs"
    }

@app.get("/health")
def health_check():
    """Health check endpoint for Docker healthcheck."""
    return {"status": "healthy"}