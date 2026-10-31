"""Remediation proposals, approvals, verification and pull requests."""

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.common import Page, get_owned, paginate, ser
from app.core.database import get_db
from app.core.deps import OrgContext, get_org_context, require_role
from app.db.models import Finding, RemediationApproval, RemediationProposal, Repository, User, VerificationRun
from app.services import jobs
from app.services.audit import audit
from app.services.remediation_service import RemediationError, open_pull_request

router = APIRouter()


@router.get("/proposals")
async def list_proposals(status: Optional[str] = None, page: Page = Depends(), ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    q = (select(RemediationProposal, Finding.title, Finding.severity, Repository.full_name).join(Finding, RemediationProposal.finding_id == Finding.id)
         .join(Repository, Finding.repository_id == Repository.id).where(RemediationProposal.organization_id == ctx.org_id))
    if status:
        q = q.where(RemediationProposal.status == status)
    return await paginate(db, q.order_by(RemediationProposal.created_at.desc()), page,
                          mapper=lambda p, t, s, r: {**ser(p, exclude=("patch",)), "finding_title": t, "finding_severity": s, "repository_name": r,
                                                     "has_patch": bool(p.patch)})


@router.get("/proposals/{pid}")
async def get_proposal(pid: uuid.UUID, ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    p = await get_owned(db, RemediationProposal, pid, ctx.org_id, "Proposal")
    f = await db.get(Finding, p.finding_id)
    repo = await db.get(Repository, f.repository_id)
    approvals = (await db.execute(select(RemediationApproval, User.email).outerjoin(User, RemediationApproval.user_id == User.id)
                                  .where(RemediationApproval.proposal_id == p.id).order_by(RemediationApproval.created_at))).all()
    verifs = (await db.execute(select(VerificationRun).where(VerificationRun.proposal_id == p.id).order_by(VerificationRun.created_at.desc()))).scalars().all()
    return {**ser(p), "finding": ser(f, include=("id", "title", "severity", "vuln_id", "finding_type", "package_name", "installed_version",
                                                 "fixed_version", "file_path", "start_line", "status")),
            "repository": ser(repo, include=("id", "full_name", "provider", "html_url")),
            "approvals": [{**ser(a), "user_email": e} for a, e in approvals], "verifications": [ser(v) for v in verifs],
            "can_open_pr": repo.provider == "github" and p.status in ("approved", "verified") and bool(p.patch)}


class DecisionIn(BaseModel):
    decision: str = Field(pattern="^(approved|rejected)$")
    comment: Optional[str] = Field(default=None, max_length=2000)


@router.post("/proposals/{pid}/decision")
async def decide(pid: uuid.UUID, body: DecisionIn, ctx: OrgContext = Depends(require_role("admin")), db: AsyncSession = Depends(get_db)):
    p = await get_owned(db, RemediationProposal, pid, ctx.org_id, "Proposal")
    if p.status not in ("proposed", "verification_failed", "verified"):
        raise HTTPException(409, f"Proposal is {p.status}")
    if body.decision == "approved" and not p.patch:
        raise HTTPException(422, "Guidance-only proposals cannot be approved for application; apply the steps manually")
    if body.decision == "approved" and not p.evidence_sufficient and not body.comment:
        raise HTTPException(422, "Evidence for this proposal is marked insufficient; approval requires a justification comment")
    db.add(RemediationApproval(proposal_id=p.id, user_id=ctx.user.id, decision=body.decision, comment=body.comment))
    prev = p.status
    if body.decision == "rejected":
        p.status = "rejected"
    elif prev == "proposed" or prev == "verification_failed":
        p.status = "approved"
    f = await db.get(Finding, p.finding_id)
    if body.decision == "approved" and f.status == "OPEN":
        f.status = "IN_PROGRESS"
    await audit(db, f"remediation.{body.decision}", org_id=ctx.org_id, user=ctx.user, resource_type="remediation_proposal", resource_id=p.id,
                details={"comment": body.comment, "previous_status": prev})
    return ser(p)


@router.post("/proposals/{pid}/verify", status_code=202)
async def verify(pid: uuid.UUID, ctx: OrgContext = Depends(require_role("member")), db: AsyncSession = Depends(get_db)):
    p = await get_owned(db, RemediationProposal, pid, ctx.org_id, "Proposal")
    if not p.patch:
        raise HTTPException(422, "Only proposals with a patch can be verified")
    if p.status not in ("approved", "verified", "verification_failed", "pr_opened"):
        raise HTTPException(409, "Proposal must be approved before verification (patches are only applied after human approval)")
    if (await db.execute(select(VerificationRun).where(VerificationRun.proposal_id == p.id, VerificationRun.status.in_(["pending", "running"])))).scalars().first():
        raise HTTPException(409, "Verification already in progress")
    vr = VerificationRun(proposal_id=p.id, status="pending")
    db.add(vr)
    await db.flush()
    jobs.enqueue("app.services.remediation_service.run_verification", str(vr.id))
    await audit(db, "remediation.verify", org_id=ctx.org_id, user=ctx.user, resource_type="verification_run", resource_id=vr.id)
    return ser(vr)


@router.post("/proposals/{pid}/pull-request")
async def pull_request(pid: uuid.UUID, ctx: OrgContext = Depends(require_role("admin")), db: AsyncSession = Depends(get_db)):
    p = await get_owned(db, RemediationProposal, pid, ctx.org_id, "Proposal")
    try:
        res = await open_pull_request(db, p, ctx.user)
    except RemediationError as e:
        raise HTTPException(422, str(e))
    except HTTPException:
        raise  # e.g. integration_required -> setup prompt in the UI
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"GitHub error: {e}")
    await audit(db, "remediation.pull_request", org_id=ctx.org_id, user=ctx.user, resource_type="remediation_proposal", resource_id=p.id, details=res)
    return res
