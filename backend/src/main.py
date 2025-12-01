from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from src.db.session import engine, Base
from src.api.v1.endpoints import programs, scans, assets, monitoring, auth, notifications, settings as settings_router, vulnerabilities
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
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Fix CORS for RateLimitExceeded
from starlette.middleware.cors import CORSMiddleware as StarletteCORSMiddleware
from fastapi.responses import JSONResponse

async def custom_rate_limit_handler(request: Request, exc: RateLimitExceeded):
    response = _rate_limit_exceeded_handler(request, exc)
    # Add CORS headers manually since exception handlers might bypass middleware in some cases
    # or if the middleware stack is not fully traversed for exceptions raised early.
    # However, usually middleware handles it. 
    # But for safety, we can ensure headers are present.
    # Actually, a better way is to ensure CORSMiddleware is the first one.
    # It is already added.
    # But slowapi handler returns a plain Response/JSONResponse.
    # Let's explicitly add headers.
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