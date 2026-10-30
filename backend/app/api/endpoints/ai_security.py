"""AI application security assessment endpoints."""

import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.common import Page, get_owned, paginate, ser
from app.core.database import get_db
from app.core.deps import OrgContext, get_org_context, require_role
from app.db.models import AISecurityAssessment, AISecurityResult, Repository
from app.services import jobs
from app.services.ai_security import MITIGATIONS, PROBES, STATIC_CHECKS
from app.services.audit import audit

router = APIRouter()


@router.get("/catalog")
async def catalog(ctx: OrgContext = Depends(get_org_context)):
    return {"categories": sorted(MITIGATIONS),
            "static_checks": [{"id": c.test_id, "category": c.category, "title": c.title, "severity": c.severity} for c in STATIC_CHECKS],
            "probes": [{"id": p["id"], "category": p["category"], "title": p["title"], "severity": p.get("severity")} for p in PROBES]}


class ProbeIn(BaseModel):
    id: str = Field(pattern=r"^[\w-]{2,40}$")
    category: str
    title: str = Field(max_length=200)
    user: str = Field(min_length=5, max_length=4000)
    judge: str = Field(pattern="^(canary|regex|forbidden_tool)$")
    regex: Optional[str] = Field(default=None, max_length=500)
    forbidden: Optional[List[str]] = None
    severity: str = Field(default="MEDIUM", pattern="^(CRITICAL|HIGH|MEDIUM|LOW)$")


class AssessmentIn(BaseModel):
    name: str = Field(min_length=3, max_length=200)
    description: Optional[str] = Field(default=None, max_length=2000)
    target_type: str = Field(pattern="^(repository|llm_endpoint)$")
    repository_id: Optional[uuid.UUID] = None
    provider: Optional[str] = Field(default=None, pattern="^(ollama|openai_compatible|anthropic)$")
    model: Optional[str] = Field(default=None, max_length=200)
    system_prompt: Optional[str] = Field(default=None, max_length=8000, description="Use {canary} to place the canary token")
    temperature: float = Field(default=0.2, ge=0, le=2)
    custom_probes: List[ProbeIn] = []


@router.post("/assessments", status_code=202)
async def create(body: AssessmentIn, ctx: OrgContext = Depends(require_role("member")), db: AsyncSession = Depends(get_db)):
    if body.target_type == "repository":
        if not body.repository_id:
            raise HTTPException(422, "repository_id required")
        await get_owned(db, Repository, body.repository_id, ctx.org_id, "Repository")
    for p in body.custom_probes:
        if p.category not in MITIGATIONS:
            raise HTTPException(422, f"Unknown category {p.category}")
    cfg: Dict[str, Any] = {"provider": body.provider, "model": body.model, "system_prompt": body.system_prompt, "temperature": body.temperature,
                           "custom_probes": [p.model_dump() for p in body.custom_probes]} if body.target_type == "llm_endpoint" else {}
    a = AISecurityAssessment(organization_id=ctx.org_id, name=body.name, description=body.description, target_type=body.target_type,
                             repository_id=body.repository_id, target_config=cfg, status="queued",
                             test_suites=["static_ai_code_checks"] if body.target_type == "repository" else ["adversarial_probes"])
    db.add(a)
    await db.flush()
    jobs.enqueue("app.services.ai_security.run_assessment", str(a.id))
    await audit(db, "ai_security.assessment_start", org_id=ctx.org_id, user=ctx.user, resource_type="ai_assessment", resource_id=a.id,
                details={"target_type": body.target_type})
    return ser(a)


@router.get("/assessments")
async def list_assessments(page: Page = Depends(), ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    return await paginate(db, select(AISecurityAssessment).where(AISecurityAssessment.organization_id == ctx.org_id)
                          .order_by(AISecurityAssessment.created_at.desc()), page)


@router.get("/assessments/{aid}")
async def get_assessment(aid: uuid.UUID, ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    a = await get_owned(db, AISecurityAssessment, aid, ctx.org_id, "Assessment")
    results = (await db.execute(select(AISecurityResult).where(AISecurityResult.assessment_id == a.id).order_by(AISecurityResult.test_id))).scalars().all()
    repo = await db.get(Repository, a.repository_id) if a.repository_id else None
    return {**ser(a), "repository_name": repo.full_name if repo else None, "results": [ser(r) for r in results]}
