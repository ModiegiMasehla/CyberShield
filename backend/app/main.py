from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api import router
from .config import settings
from .database import Base, SessionLocal, engine
from .middleware import RateLimitMiddleware, SecurityHeadersMiddleware
from .seed import seed


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if settings.auto_create_schema:
        Base.metadata.create_all(bind=engine)
    if settings.should_seed:
        db = SessionLocal()
        try:
            seed(db)
        finally:
            db.close()
    yield


app = FastAPI(
    title="CyberShield API",
    version="1.1.0",
    description="Defensive cybersecurity learning and monitoring platform.",
    lifespan=lifespan,
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None if settings.is_production else "/redoc",
    openapi_url=None if settings.is_production else "/openapi.json",
)

origins = [x.strip() for x in settings.cors_origins.split(",") if x.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

app.include_router(router)


@app.get("/")
def root():
    return {
        "name": "CyberShield",
        "docs": "/docs",
        "authorization_notice": "Only scan systems you own or have explicit permission to test.",
    }


@app.get("/health")
def health():
    return {"status": "ok", "service": "cybershield"}
