"""Evaluation datasets, runs and comparisons."""

import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.common import Page, get_owned, paginate, ser
from app.core.database import get_db
from app.core.deps import OrgContext, get_org_context, require_role
from app.db.models import EvaluationCase, EvaluationDataset, EvaluationResult, EvaluationRun
from app.services import jobs
from app.services.audit import audit

router = APIRouter()


def _visible(ctx):
    return or_(EvaluationDataset.organization_id.is_(None), EvaluationDataset.organization_id == ctx.org_id)


@router.get("/datasets")
async def datasets(ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(EvaluationDataset, func.count(EvaluationCase.id)).outerjoin(EvaluationCase).where(_visible(ctx))
                             .group_by(EvaluationDataset.id).order_by(EvaluationDataset.name))).all()
    return [{**ser(d), "case_count": n} for d, n in rows]


@router.get("/datasets/{ds_id}")
async def dataset(ds_id: uuid.UUID, ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    d = await db.get(EvaluationDataset, ds_id)
    if not d or (d.organization_id and d.organization_id != ctx.org_id):
        raise HTTPException(404, "Dataset not found")
    cases = (await db.execute(select(EvaluationCase).where(EvaluationCase.dataset_id == d.id).order_by(EvaluationCase.case_key))).scalars().all()
    return {**ser(d), "cases": [ser(c) for c in cases]}


class CaseIn(BaseModel):
    case_key: str = Field(pattern=r"^[\w.-]{2,100}$")
    input: Dict[str, Any]
    expected: Dict[str, Any]
    tags: List[str] = []


class DatasetIn(BaseModel):
    name: str = Field(min_length=3, max_length=200)
    description: Optional[str] = None
    task_type: str = Field(pattern="^(vuln_analysis|cve_matching)$")
    cases: List[CaseIn] = Field(min_length=1, max_length=500)


def _validate_case(task: str, c: CaseIn) -> None:
    if task == "vuln_analysis":
        if not {"language", "code"} <= c.input.keys() or "vulnerable" not in c.expected:
            raise HTTPException(422, f"{c.case_key}: vuln_analysis cases need input.language, input.code and expected.vulnerable")
        if c.expected["vulnerable"] and not {"cwe", "severity", "remediation_keywords"} <= c.expected.keys():
            raise HTTPException(422, f"{c.case_key}: vulnerable cases need expected.cwe, expected.severity, expected.remediation_keywords")
    else:
        if not {"ecosystem", "package", "version"} <= c.input.keys() or "cve_any" not in c.expected:
            raise HTTPException(422, f"{c.case_key}: cve_matching cases need input.ecosystem/package/version and expected.cve_any")


@router.post("/datasets", status_code=201)
async def create_dataset(body: DatasetIn, ctx: OrgContext = Depends(require_role("member")), db: AsyncSession = Depends(get_db)):
    for c in body.cases:
        _validate_case(body.task_type, c)
    d = EvaluationDataset(organization_id=ctx.org_id, name=body.name, description=body.description, task_type=body.task_type)
    db.add(d)
    await db.flush()
    for c in body.cases:
        db.add(EvaluationCase(dataset_id=d.id, case_key=c.case_key, input=c.input, expected=c.expected, tags=c.tags))
    await audit(db, "evaluation.dataset_create", org_id=ctx.org_id, user=ctx.user, resource_id=d.id, details={"cases": len(body.cases)})
    return ser(d)


class RunIn(BaseModel):
    dataset_id: uuid.UUID
    modes: List[str] = Field(default=["base", "rag", "agentic_rag"])
    provider: Optional[str] = Field(default=None, pattern="^(ollama|openai_compatible|anthropic)$")
    model: Optional[str] = Field(default=None, max_length=200)
    case_limit: Optional[int] = Field(default=None, ge=1, le=500)
    name: Optional[str] = Field(default=None, max_length=200)


@router.post("/runs", status_code=202)
async def create_runs(body: RunIn, ctx: OrgContext = Depends(require_role("member")), db: AsyncSession = Depends(get_db)):
    d = await db.get(EvaluationDataset, body.dataset_id)
    if not d or (d.organization_id and d.organization_id != ctx.org_id):
        raise HTTPException(404, "Dataset not found")
    if set(body.modes) - {"base", "rag", "agentic_rag"}:
        raise HTTPException(422, "modes must be base, rag, agentic_rag")
    from app.llm.provider import get_provider

    p = get_provider(body.provider, body.model)
    runs = []
    for mode in body.modes:
        r = EvaluationRun(organization_id=ctx.org_id, dataset_id=d.id, mode=mode, provider=p.name, model=p.model, case_limit=body.case_limit,
                          name=body.name or f"{d.name} · {mode} · {p.model}", status="queued")
        db.add(r)
        await db.flush()
        jobs.enqueue("app.evals.engine.run_evaluation", str(r.id))
        runs.append(ser(r))
    await audit(db, "evaluation.run", org_id=ctx.org_id, user=ctx.user, details={"dataset": d.name, "modes": body.modes, "model": p.model})
    return runs


@router.get("/runs")
async def list_runs(dataset_id: Optional[uuid.UUID] = None, page: Page = Depends(), ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    q = select(EvaluationRun, EvaluationDataset.name, EvaluationDataset.task_type).join(EvaluationDataset).where(EvaluationRun.organization_id == ctx.org_id)
    if dataset_id:
        q = q.where(EvaluationRun.dataset_id == dataset_id)
    return await paginate(db, q.order_by(EvaluationRun.created_at.desc()), page,
                          mapper=lambda r, n, t: {**ser(r), "dataset_name": n, "task_type": t})


@router.get("/runs/{run_id}")
async def get_run(run_id: uuid.UUID, ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    r = await get_owned(db, EvaluationRun, run_id, ctx.org_id, "Run")
    rows = (await db.execute(select(EvaluationResult, EvaluationCase.case_key, EvaluationCase.expected).join(EvaluationCase)
                             .where(EvaluationResult.run_id == r.id).order_by(EvaluationCase.case_key))).all()
    d = await db.get(EvaluationDataset, r.dataset_id)
    return {**ser(r), "dataset_name": d.name, "task_type": d.task_type,
            "results": [{**ser(res), "case_key": k, "expected": e} for res, k, e in rows]}


@router.get("/compare")
async def compare(dataset_id: uuid.UUID, ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    """Latest completed run per (mode, model) for a dataset. Unrun configurations are listed as not run."""
    runs = (await db.execute(select(EvaluationRun).where(EvaluationRun.organization_id == ctx.org_id, EvaluationRun.dataset_id == dataset_id)
                             .order_by(EvaluationRun.created_at.desc()))).scalars().all()
    latest: Dict[str, Any] = {}
    for r in runs:
        key = f"{r.mode}|{r.model}"
        if key not in latest and r.status == "completed":
            latest[key] = {"run_id": str(r.id), "mode": r.mode, "provider": r.provider, "model": r.model, "metrics": r.metrics,
                           "completed_at": r.completed_at.isoformat() if r.completed_at else None}
    modes_run = {v["mode"] for v in latest.values()}
    return {"configurations": list(latest.values()), "not_run": [m for m in ("base", "rag", "agentic_rag") if m not in modes_run]}
