"""Agent investigation endpoints."""

import uuid
from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.graph import SPECIALISTS
from app.api.common import Page, get_owned, paginate, ser
from app.core.database import get_db
from app.core.deps import OrgContext, get_org_context
from app.db.models import AgentEvent, AgentInvestigation, Finding, MCPToolExecution, Repository
from app.integrations.registry import resolve_provider

router = APIRouter()

AGENTS = [
    {"name": "supervisor", "role": "Security Supervisor", "responsibility": "Plans the investigation, routes to specialists, retries failures, assembles the result.", "tools": []},
    {"name": "vulnerability_research", "role": "Vulnerability Research", "responsibility": "Structured intel (NVD/OSV/GHSA/KEV), exact version confirmation, evidence retrieval.",
     "tools": ["intel.lookup", "rag.retrieve", "mcp:osv_query_package"]},
    {"name": "code_analysis", "role": "Code Security Analysis", "responsibility": "Reads code context, finds package usages, describes attack paths; separates confirmed facts from hypotheses.",
     "tools": ["mcp:read_file", "mcp:search_code"]},
    {"name": "risk_assessment", "role": "Risk Assessment", "responsibility": "Deterministic, explainable risk score and priority; model explains impact.", "tools": []},
    {"name": "remediation", "role": "Remediation", "responsibility": "Dependency upgrade patches, model-proposed code patches validated as diffs, side effects.",
     "tools": ["manifest.read", "patch.generate"]},
    {"name": "verification", "role": "Verification", "responsibility": "Applies approved patches to an isolated snapshot and re-runs relevant scanners before/after.",
     "tools": ["snapshot", "git apply", "scanners"]},
]


@router.get("/catalog")
async def catalog(ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    p = await resolve_provider(db, ctx.org_id)
    return {"agents": AGENTS, "graph": ["START", "supervisor", *SPECIALISTS, "finalize", "END"], "provider": await p.health()}


@router.get("/investigations")
async def list_investigations(status: Optional[str] = None, finding_id: Optional[uuid.UUID] = None, page: Page = Depends(),
                              ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    q = (select(AgentInvestigation, Finding.title, Finding.severity, Repository.full_name).join(Finding, AgentInvestigation.finding_id == Finding.id)
         .join(Repository, Finding.repository_id == Repository.id).where(AgentInvestigation.organization_id == ctx.org_id))
    if status:
        q = q.where(AgentInvestigation.status == status)
    if finding_id:
        q = q.where(AgentInvestigation.finding_id == finding_id)
    fields = ("id", "finding_id", "status", "mode", "model", "summary", "started_at", "completed_at", "tokens_in", "tokens_out", "latency_ms",
              "error_message", "created_at")
    return await paginate(db, q.order_by(AgentInvestigation.created_at.desc()), page,
                          mapper=lambda i, t, s, r: {**ser(i, include=fields), "finding_title": t, "finding_severity": s, "repository_name": r,
                                                     "priority": (i.risk_assessment or {}).get("priority")})


@router.get("/investigations/{inv_id}")
async def get_investigation(inv_id: uuid.UUID, ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    inv = await get_owned(db, AgentInvestigation, inv_id, ctx.org_id, "Investigation")
    f = await db.get(Finding, inv.finding_id)
    events = (await db.execute(select(AgentEvent).where(AgentEvent.investigation_id == inv.id).order_by(AgentEvent.sequence))).scalars().all()
    tools = (await db.execute(select(MCPToolExecution).where(MCPToolExecution.investigation_id == inv.id).order_by(MCPToolExecution.created_at))).scalars().all()
    return {**ser(inv), "finding": ser(f, include=("id", "title", "severity", "vuln_id", "finding_type", "package_name", "file_path", "start_line")),
            "events": [ser(e) for e in events], "tool_executions": [ser(t) for t in tools]}
