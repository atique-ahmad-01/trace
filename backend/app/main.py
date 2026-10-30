"""
TRACE Backend Application

Agentic Application Security & Vulnerability Intelligence Platform
"""

import asyncio
import time
from collections import defaultdict
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from loguru import logger
from sqlalchemy import text

from app.api import api_router
from app.core.config import BACKEND_DIR, settings
from app.core.logging import setup_logging

setup_logging()


def run_migrations() -> None:
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    command.upgrade(cfg, "head")


async def recover_interrupted_jobs() -> None:
    """In-process jobs do not survive a restart; mark them failed instead of leaving them 'running' forever."""
    from datetime import datetime, timezone

    from sqlalchemy import update

    from app.core.database import async_session_maker
    from app.db.models import AgentInvestigation, AISecurityAssessment, EvaluationRun, Scan, VerificationRun
    from app.services import jobs

    if jobs.backend_name() == "rq":
        return  # RQ workers own job state
    now, msg = datetime.now(timezone.utc), "Interrupted by backend restart — please re-run"
    async with async_session_maker() as db:
        for model, col, active, failed in (
            (Scan, Scan.status, ["PENDING", "RUNNING"], "FAILED"),
            (AgentInvestigation, AgentInvestigation.status, ["queued", "running"], "failed"),
            (AISecurityAssessment, AISecurityAssessment.status, ["queued", "running"], "failed"),
            (EvaluationRun, EvaluationRun.status, ["queued", "running"], "failed"),
            (VerificationRun, VerificationRun.status, ["pending", "running"], "error"),
        ):
            res = await db.execute(update(model).where(col.in_(active)).values(status=failed, error_message=msg))
            if res.rowcount:
                logger.warning(f"Marked {res.rowcount} interrupted {model.__tablename__} as {failed}")
        await db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting TRACE {settings.APP_VERSION} ({settings.ENVIRONMENT}, db={'sqlite' if settings.is_sqlite else 'postgresql'})")
    if settings.ENVIRONMENT != "test":
        await asyncio.to_thread(run_migrations)
        await recover_interrupted_jobs()
        if settings.SEED_DEMO_DATA:
            from app.db.seed.seed import seed

            try:
                await seed()
            except Exception:  # noqa: BLE001
                logger.exception("Seeding failed")
    if settings.ENVIRONMENT == "production" and settings.SECRET_KEY.startswith("dev-insecure"):
        raise RuntimeError("SECRET_KEY / JWT_SECRET_KEY must be set in production")
    yield
    logger.info("TRACE backend stopped")


app = FastAPI(
    title=f"{settings.APP_NAME} API",
    version=settings.APP_VERSION,
    description="Agentic Application Security & Vulnerability Intelligence Platform — Trace every risk to a verified fix.",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(CORSMiddleware, allow_origins=settings.CORS_ORIGINS, allow_credentials=True, allow_methods=["*"],
                   allow_headers=["Authorization", "Content-Type", "X-Organization-Id"])
if settings.ENVIRONMENT == "production":
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.ALLOWED_HOSTS)

_buckets: dict = defaultdict(lambda: [settings.RATE_LIMIT_PER_MINUTE, time.monotonic()])


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    # Token-bucket rate limit per client IP (webhooks and health checks exempt).
    path = request.url.path
    if settings.RATE_LIMIT_PER_MINUTE > 0 and path.startswith("/api/") and not path.startswith("/api/v1/webhooks"):
        ip = request.client.host if request.client else "unknown"
        bucket = _buckets[ip]
        now = time.monotonic()
        bucket[0] = min(settings.RATE_LIMIT_PER_MINUTE, bucket[0] + (now - bucket[1]) * settings.RATE_LIMIT_PER_MINUTE / 60)
        bucket[1] = now
        if bucket[0] < 1:
            return JSONResponse({"detail": "Rate limit exceeded"}, status_code=429, headers={"Retry-After": "5"})
        bucket[0] -= 1
    start = time.monotonic()
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Response-Time-ms"] = str(int((time.monotonic() - start) * 1000))
    return response


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=422, content={"detail": [{"loc": e["loc"], "msg": e["msg"]} for e in exc.errors()]})


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.opt(exception=exc).error(f"Unhandled error on {request.method} {request.url.path}")
    return JSONResponse(status_code=500, content={"detail": "Internal server error", "error": type(exc).__name__ if settings.DEBUG else None})


@app.get("/", include_in_schema=False)
async def root():
    return {"name": settings.APP_NAME, "version": settings.APP_VERSION, "docs": "/docs"}


@app.get("/health", tags=["System"])
async def health():
    return {"status": "healthy", "version": settings.APP_VERSION, "environment": settings.ENVIRONMENT}


@app.get("/ready", tags=["System"])
async def ready():
    from app.core.database import async_session_maker

    try:
        async with async_session_maker() as s:
            await s.execute(text("SELECT 1"))
        return {"status": "ready", "database": "connected"}
    except Exception as e:  # noqa: BLE001
        return JSONResponse(status_code=503, content={"status": "not_ready", "database": "disconnected", "error": type(e).__name__})


app.include_router(api_router, prefix="/api/v1")
