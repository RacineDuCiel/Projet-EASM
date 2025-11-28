from fastapi import FastAPI
from contextlib import asynccontextmanager
from .database import engine, Base
from .routers import programs, scans, assets

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    # Shutdown: Close connection (optional, engine handles it)

app = FastAPI(title="EASM Platform API", lifespan=lifespan)

app.include_router(programs.router)
app.include_router(scans.router)
app.include_router(assets.router)

@app.get("/")
def read_root():
    return {"status": "EASM API is running", "docs": "/docs"}