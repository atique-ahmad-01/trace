"""Finding endpoints: filtering, detail, status updates, investigation trigger."""

import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import case, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.common import Page, get_owned, paginate, ser
from app.core.database import get_db
from app.core.deps import OrgContext, get_org_context, require_role
from app.integrations import registry as integrations
from app.db.models import AgentInvestigation, Finding, FindingStatus, RemediationProposal, Repository, VerificationRun, VulnerabilityRecord
from app.intel.service import record_to_dict
from app.services.audit import audit

router = APIRouter()

SEV_RANK = case({"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}, value=Finding.severity, else_=5)


def _filtered(ctx: OrgContext, severity, status, repository_id, scanner, finding_type, q, since, until, demo):
    stmt = select(Finding, Repository.full_name).join(Repository).where(Finding.organization_id == ctx.org_id)
    if severity:
        stmt = stmt.where(Finding.severity.in_([s.strip().upper() for s in severity.split(",")]))
    if status:
        stmt = stmt.where(Finding.status.in_([s.strip().upper() for s in status.split(",")]))
    if repository_id:
        stmt = stmt.where(Finding.repository_id == repository_id)
    if scanner:
        stmt = stmt.where(Finding.scanner_name == scanner)
    if finding_type:
        stmt = stmt.where(Finding.finding_type.in_(finding_type.split(",")))
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(Finding.title.ilike(like), Finding.vuln_id.ilike(like), Finding.package_name.ilike(like), Finding.file_path.ilike(like)))
    if since:
        stmt = stmt.where(Finding.first_seen_at >= since)
    if until:
        stmt = stmt.where(Finding.first_seen_at <= until)
    if demo is not None:
        stmt = stmt.where(Finding.is_demo.is_(demo))
    return stmt


LIST_FIELDS = ("id", "title", "severity", "status", "finding_type", "scanner_name", "detected_by", "vuln_id", "cvss_score", "package_name",
               "installed_version", "fixed_version", "file_path", "start_line", "repository_id", "first_seen_at", "last_seen_at",
               "priority", "risk_score", "is_demo", "cwe_ids")


@router.get("")
async def list_findings(severity: Optional[str] = None, status: Optional[str] = None, repository_id: Optional[uuid.UUID] = None,
                        scanner: Optional[str] = None, finding_type: Optional[str] = None, q: Optional[str] = None,
                        since: Optional[datetime] = None, until: Optional[datetime] = None, demo: Optional[bool] = None,
                        sort: str = "severity", page: Page = Depends(), ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    stmt = _filtered(ctx, severity, status, repository_id, scanner, finding_type, q, since, until, demo)
    order = {"severity": (SEV_RANK, Finding.cvss_score.desc().nullslast()), "newest": (Finding.first_seen_at.desc(),),
             "risk": (Finding.risk_score.desc().nullslast(), SEV_RANK)}.get(sort, (SEV_RANK,))
    return await paginate(db, stmt.order_by(*order), page, mapper=lambda f, name: {**ser(f, include=LIST_FIELDS), "repository_name": name})


@router.get("/{finding_id}")
async def get_finding(finding_id: uuid.UUID, ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    f = await get_owned(db, Finding, finding_id, ctx.org_id, "Finding")
    repo = await db.get(Repository, f.repository_id)
    rec = (await db.execute(select(VulnerabilityRecord).where(VulnerabilityRecord.vuln_id == f.vuln_id))).scalar_one_or_none() if f.vuln_id else None
    invs = (await db.execute(select(AgentInvestigation).where(AgentInvestigation.finding_id == f.id).order_by(AgentInvestigation.created_at.desc()))).scalars().all()
    props = (await db.execute(select(RemediationProposal).where(RemediationProposal.finding_id == f.id).order_by(RemediationProposal.created_at.desc()))).scalars().all()
    verifs = []
    for p in props:
        verifs += [{**ser(v), "proposal_id": str(p.id)} for v in (await db.execute(select(VerificationRun).where(VerificationRun.proposal_id == p.id)
                                                                                   .order_by(VerificationRun.created_at.desc()))).scalars()]
    return {**ser(f, exclude=("raw_data",)), "repository": ser(repo, include=("id", "full_name", "provider", "html_url", "default_branch")),
            "intelligence": record_to_dict(rec) if rec else None,
            "investigations": [ser(i, include=("id", "status", "mode", "model", "summary", "created_at", "completed_at", "error_message")) for i in invs],
            "proposals": [ser(p) for p in props], "verifications": verifs}


class FindingUpdate(BaseModel):
    status: str = Field(pattern="^(OPEN|IN_PROGRESS|RESOLVED|FALSE_POSITIVE|ACCEPTED_RISK)$")
    reason: Optional[str] = Field(default=None, max_length=1000)


@router.patch("/{finding_id}")
async def update_finding(finding_id: uuid.UUID, body: FindingUpdate, ctx: OrgContext = Depends(require_role("member")), db: AsyncSession = Depends(get_db)):
    f = await get_owned(db, Finding, finding_id, ctx.org_id, "Finding")
    if body.status in ("FALSE_POSITIVE", "ACCEPTED_RISK") and not body.reason:
        raise HTTPException(422, "A reason is required for false positive / accepted risk")
    old = f.status
    f.status = body.status
    f.resolved_at = datetime.utcnow() if body.status == FindingStatus.RESOLVED.value else None
    await audit(db, "finding.status_change", org_id=ctx.org_id, user=ctx.user, resource_type="finding", resource_id=f.id,
                details={"from": old, "to": body.status, "reason": body.reason})
    return ser(f, include=LIST_FIELDS)


class InvestigateIn(BaseModel):
    mode: str = Field(default="agentic_rag", pattern="^(agentic_rag|rag|base)$")
    provider: Optional[str] = Field(default=None, pattern="^(ollama|openai_compatible|anthropic)$")
    model: Optional[str] = Field(default=None, max_length=200)


@router.post("/{finding_id}/investigate", status_code=202)
async def investigate(finding_id: uuid.UUID, body: InvestigateIn = InvestigateIn(), ctx: OrgContext = Depends(require_role("member")),
                      db: AsyncSession = Depends(get_db)):
    from app.agents.service import create_investigation

    f = await get_owned(db, Finding, finding_id, ctx.org_id, "Finding")
    running = (await db.execute(select(AgentInvestigation).where(AgentInvestigation.finding_id == f.id,
                                                                 AgentInvestigation.status.in_(["queued", "running"])))).scalars().first()
    if running:
        raise HTTPException(409, "An investigation is already running for this finding")
    await integrations.require(db, ctx.org_id, "model_provider")
    inv = await create_investigation(db, f, user_id=ctx.user.id, mode=body.mode, provider=body.provider, model=body.model)
    await audit(db, "investigation.start", org_id=ctx.org_id, user=ctx.user, resource_type="investigation", resource_id=inv.id,
                details={"finding": str(f.id), "mode": body.mode, "model": inv.model})
    return ser(inv)
