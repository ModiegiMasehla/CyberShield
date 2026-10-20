import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .api import router
from .config import settings
from .database import Base, SessionLocal, engine
from .middleware import RateLimitMiddleware, RequestContextMiddleware, SecurityHeadersMiddleware
from .seed import seed

logging.basicConfig(level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)  # its INFO lines contain full request URLs
logger = logging.getLogger("cybershield")


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

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestContextMiddleware)  # added last = outermost: tags every response, even 429s


@app.exception_handler(Exception)
async def unhandled_error(request: Request, exc: Exception):
    # Full details go to the server log only; the client gets a generic, consistently shaped error.
    request_id = getattr(request.state, "request_id", None)
    logger.error("unhandled error request_id=%s", request_id, exc_info=exc)
    return JSONResponse({"detail": "Internal server error", "request_id": request_id}, status_code=500)


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
