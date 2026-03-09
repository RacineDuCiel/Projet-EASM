from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from contextlib import asynccontextmanager
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import logging
import re

from src.db.session import engine, AsyncSessionLocal
from src.api.v1.endpoints import programs, scans, assets, monitoring, auth, notifications, settings as settings_router, vulnerabilities, logs, passive_intel, security_posture
from src.core.config import settings
from src.core.logging import setup_logging


def get_client_ip(request: Request) -> str:
    """
    Get the real client IP address, handling X-Forwarded-For header.
    In production behind a trusted reverse proxy, extracts the original client IP.
    """
    x_forwarded_for = request.headers.get("X-Forwarded-For")
    if x_forwarded_for:
        # Take the first IP in the chain (original client)
        # This assumes the first proxy is trusted
        ips = [ip.strip() for ip in x_forwarded_for.split(",")]
        if ips:
            return ips[0]
    
    x_real_ip = request.headers.get("X-Real-IP")
    if x_real_ip:
        return x_real_ip
    
    return request.client.host if request.client else "127.0.0.1"


# Rate limiter configuration using custom key function
limiter = Limiter(
    key_func=get_client_ip,
    default_limits=["100/hour"] if settings.ENVIRONMENT == "production" else ["1000/hour"]
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Configure logging
    setup_logging()
    logger = logging.getLogger("src.main")
    logger.info("Starting EASM Platform API...")

    # NOTE: Database schema is managed by Alembic migrations.
    # Do NOT use Base.metadata.create_all() here.

    # Recovery: Resume interrupted scans
    async with AsyncSessionLocal() as db:
        try:
            from src.services.scan_service import ScanService
            await ScanService.resume_interrupted_scans(db)
            
            # Bootstrapping: Create superuser if needed
            from src.db.init_db import init_db
            await init_db(db)
        except Exception as e:
            logger.error(f"Failed to run startup tasks: {e}")
    
    yield
    
    # Shutdown: Clean shutdown
    logger.info("Shutting down EASM Platform API...")
    # Close database connections
    await engine.dispose()

app = FastAPI(
    title="EASM Platform API",
    lifespan=lifespan,
    description="External Attack Surface Management Platform",
    version="1.0.0",
    docs_url="/api/docs" if settings.ENVIRONMENT != "production" else None,
    redoc_url="/api/redoc" if settings.ENVIRONMENT != "production" else None,
)

# CORS Configuration - loaded from environment
cors_origins = settings.cors_origins_list
# In development, also allow any origin on port 5173 (LAN access)
cors_origin_regex = r"^http://(localhost|127\.0\.0\.1|(\d{1,3}\.){3}\d{1,3}):5173$" if settings.ENVIRONMENT != "production" else None

# GZip compression - added BEFORE CORS so CORS runs first
app.add_middleware(GZipMiddleware, minimum_size=500)

# Trusted Host middleware (production only)
if settings.ENVIRONMENT == "production":
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.allowed_hosts_list
    )

# Security Headers Middleware
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)
    
    # Prevent MIME type sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    
    # Prevent clickjacking
    response.headers["X-Frame-Options"] = "DENY"
    
    # XSS Protection
    response.headers["X-XSS-Protection"] = "1; mode=block"
    
    # Referrer Policy
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    # Content Security Policy (relaxed for API)
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none';"
    
    # HSTS (only in production with HTTPS)
    if settings.ENVIRONMENT == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    
    # Permissions Policy
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    
    return response

# CORS middleware - added LAST so it runs FIRST and handles all responses including errors
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_origin_regex=cors_origin_regex,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],  # Allow frontend to read response headers
)

# Add rate limiting
app.state.limiter = limiter

def _is_allowed_origin(origin: str | None) -> bool:
    """Check if an origin is allowed by CORS (static list or dev regex)."""
    if not origin:
        return False
    if origin in cors_origins:
        return True
    if cors_origin_regex and re.match(cors_origin_regex, origin):
        return True
    return False

async def custom_rate_limit_handler(request: Request, exc: RateLimitExceeded):
    """
    Custom handler for RateLimitExceeded to ensure CORS headers are present.
    """
    response = _rate_limit_exceeded_handler(request, exc)

    # Manually add CORS headers for rate limit responses
    origin = request.headers.get("origin")
    if _is_allowed_origin(origin):
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "*"
    return response

app.add_exception_handler(RateLimitExceeded, custom_rate_limit_handler)

# Global exception handler to log and add CORS headers on 500 errors
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Catch all unhandled exceptions, log them, and return a JSON response with CORS headers.
    """
    import traceback
    logger = logging.getLogger("src.main")
    logger.error(f"Unhandled exception on {request.method} {request.url.path}: {exc}")
    logger.error(traceback.format_exc())
    
    from fastapi.responses import JSONResponse
    response = JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}  # Generic message for security
    )
    
    # Add CORS headers
    origin = request.headers.get("origin")
    if _is_allowed_origin(origin):
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "*"

    return response

# Include Routers
app.include_router(auth.router, prefix="/api/v1", tags=["Authentication"])
app.include_router(programs.router, prefix="/api/v1", tags=["Programs"])
app.include_router(scans.router, prefix="/api/v1", tags=["Scans"])
app.include_router(assets.router, prefix="/api/v1", tags=["Assets"])
app.include_router(monitoring.router, prefix="/api/v1", tags=["Monitoring"])
app.include_router(notifications.router, prefix="/api/v1", tags=["Notifications"])
app.include_router(settings_router.router, prefix="/api/v1", tags=["Settings"])
app.include_router(vulnerabilities.router, prefix="/api/v1/vulnerabilities", tags=["Vulnerabilities"])
app.include_router(logs.router, prefix="/api/v1/logs", tags=["System Logs"])
app.include_router(passive_intel.router, prefix="/api/v1", tags=["Passive Intelligence"])
app.include_router(security_posture.router, prefix="/api/v1/security", tags=["Security Posture"])

@app.get("/health")
def health_check():
    """Health check endpoint for Docker healthcheck."""
    return {"status": "healthy"}
