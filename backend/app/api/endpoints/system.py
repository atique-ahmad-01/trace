"""Service status for the UI (scanners, model provider, vector store, jobs, intel sync)."""

import asyncio

from fastapi import APIRouter, Depends
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.common import ser
from app.core.config import settings
from app.core.database import get_db
from app.core.deps import OrgContext, get_org_context
from app.db.models import IntelSyncState
from app.integrations.github import app_configured
from app.llm.provider import get_provider
from app.rag import engine as rag
from app.scanners.adapters import scanner_status
from app.services import jobs

router = APIRouter()


@router.get("/status")
async def status(ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    await db.execute(text("SELECT 1"))
    provider = get_provider()
    llm, scanners, rag_stats = await asyncio.gather(provider.health(), asyncio.to_thread(scanner_status), rag.stats(db))
    syncs = [ser(s) for s in (await db.execute(select(IntelSyncState))).scalars()]
    return {
        "database": {"status": "ok", "engine": "sqlite" if settings.is_sqlite else "postgresql"},
        "jobs": jobs.status(),
        "model_provider": llm,
        "source_to_hosted_llm_allowed": settings.ALLOW_SOURCE_TO_HOSTED_LLM,
        "scanners": scanners,
        "rag": rag_stats,
        "intel_sync": syncs,
        "github": {"app_configured": app_configured(), "webhook_secret_configured": bool(settings.GITHUB_WEBHOOK_SECRET),
                   "env_token_configured": bool(settings.GITHUB_TOKEN)},
        "observability": {"langfuse": bool(settings.LANGFUSE_PUBLIC_KEY and settings.LANGFUSE_SECRET_KEY)},
    }
