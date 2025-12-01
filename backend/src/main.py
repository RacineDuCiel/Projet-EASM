from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.middleware.cors import CORSMiddleware as StarletteCORSMiddleware
from fastapi.responses import JSONResponse
import logging

from src.db.session import engine, Base, AsyncSessionLocal
from src.api.v1.endpoints import programs, scans, assets, monitoring, auth, notifications, settings as settings_router, vulnerabilities
from src.core.config import settings
from src.core.logging import setup_logging

# Rate limiter configuration
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["100/hour"] if settings.ENVIRONMENT == "production" else ["1000/hour"]
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Configure logging and create tables
    setup_logging()
    logger = logging.getLogger("src.main")
    logger.info("Starting EASM Platform API...")
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    # Recovery: Resume interrupted scans
    async with AsyncSessionLocal() as db:
        try:
            # Patch Enum if needed (PostgreSQL specific)
            from sqlalchemy import text
            try:
                await db.execute(text("ALTER TYPE scanstatus ADD VALUE IF NOT EXISTS 'stopped'"))
                await db.commit()
            except Exception as e:
                logger.warning(f"Could not alter enum type (might be sqlite or already exists): {e}")

            from src.services.scan_service import ScanService
            await ScanService.resume_interrupted_scans(db)
        except Exception as e:
            logger.error(f"Failed to run scan recovery: {e}")
    
    yield
    
    # Shutdown
    logger.info("Shutting down EASM Platform API...")

app = FastAPI(
    title="EASM Platform API",
    lifespan=lifespan,
    description="External Attack Surface Management Platform",
    version="1.0.0"
)

# CORS Configuration
origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add rate limiting
app.state.limiter = limiter

async def custom_rate_limit_handler(request: Request, exc: RateLimitExceeded):
    """
    Custom handler for RateLimitExceeded to ensure CORS headers are present.
    """
    response = _rate_limit_exceeded_handler(request, exc)
    
    # Manually add CORS headers for rate limit responses
    origin = request.headers.get("origin")
    if origin in origins:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "*"
    return response

app.add_exception_handler(RateLimitExceeded, custom_rate_limit_handler)

# Include Routers
app.include_router(auth.router, prefix="/api/v1", tags=["Authentication"])
app.include_router(programs.router, prefix="/api/v1", tags=["Programs"])
app.include_router(scans.router, prefix="/api/v1", tags=["Scans"])
app.include_router(assets.router, prefix="/api/v1", tags=["Assets"])
app.include_router(monitoring.router, prefix="/api/v1", tags=["Monitoring"])
app.include_router(notifications.router, prefix="/api/v1", tags=["Notifications"])
app.include_router(settings_router.router, prefix="/api/v1", tags=["Settings"])
app.include_router(vulnerabilities.router, prefix="/api/v1/vulnerabilities", tags=["Vulnerabilities"])

@app.get("/health")
def health_check():
    """Health check endpoint for Docker healthcheck."""
    return {"status": "healthy"}