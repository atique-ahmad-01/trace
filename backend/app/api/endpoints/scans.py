"""Scan endpoints."""

import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.common import Page, get_owned, paginate, ser
from app.core.database import get_db
from app.core.deps import OrgContext, get_org_context, require_role
from app.db.models import Repository, Scan, ScannerExecution
from app.scanners.adapters import SCANNERS, scanner_status
from app.services import jobs
from app.services.audit import audit

router = APIRouter()


class ScanIn(BaseModel):
    repository_id: uuid.UUID
    branch: Optional[str] = Field(default=None, max_length=200, pattern=r"^[\w./-]+$")
    commit_sha: Optional[str] = Field(default=None, pattern=r"^[0-9a-f]{7,40}$")
    scanners: Optional[List[str]] = None
    auto_investigate: bool = False


async def queue_scan(db: AsyncSession, repo: Repository, *, trigger: str, user_id=None, branch=None, commit=None, scanners=None, auto_investigate=False) -> Scan:
    scan = Scan(organization_id=repo.organization_id, repository_id=repo.id, branch=branch or repo.default_branch, commit_sha=commit,
                trigger=trigger, triggered_by=user_id, scanners_requested=scanners or [], is_demo=repo.is_demo, auto_investigate=auto_investigate,
                log=[])
    db.add(scan)
    await db.flush()
    jobs.enqueue("app.services.scan_service.run_scan", str(scan.id))
    return scan


@router.post("", status_code=202)
async def create_scan(body: ScanIn, ctx: OrgContext = Depends(require_role("member")), db: AsyncSession = Depends(get_db)):
    repo = await get_owned(db, Repository, body.repository_id, ctx.org_id, "Repository")
    if body.scanners and set(body.scanners) - set(SCANNERS):
        raise HTTPException(422, f"Unknown scanners; valid: {sorted(SCANNERS)}")
    active = (await db.execute(select(Scan).where(Scan.repository_id == repo.id, Scan.status.in_(["PENDING", "RUNNING"])))).scalars().first()
    if active:
        raise HTTPException(409, "A scan is already running for this repository")
    scan = await queue_scan(db, repo, trigger="manual", user_id=ctx.user.id, branch=body.branch, commit=body.commit_sha,
                            scanners=body.scanners, auto_investigate=body.auto_investigate)
    await audit(db, "scan.trigger", org_id=ctx.org_id, user=ctx.user, resource_type="scan", resource_id=scan.id, details={"repository": repo.full_name})
    return ser(scan)


@router.get("")
async def list_scans(repository_id: Optional[uuid.UUID] = None, status: Optional[str] = None, page: Page = Depends(),
                     ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    q = select(Scan, Repository.full_name).join(Repository).where(Scan.organization_id == ctx.org_id)
    if repository_id:
        q = q.where(Scan.repository_id == repository_id)
    if status:
        q = q.where(Scan.status == status.upper())
    return await paginate(db, q.order_by(Scan.created_at.desc()), page, mapper=lambda s, name: {**ser(s, exclude=("log",)), "repository_name": name})


@router.get("/scanners")
async def scanners(ctx: OrgContext = Depends(get_org_context)):
    return scanner_status()


@router.get("/{scan_id}")
async def get_scan(scan_id: uuid.UUID, ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    scan = await get_owned(db, Scan, scan_id, ctx.org_id, "Scan")
    repo = await db.get(Repository, scan.repository_id)
    execs = (await db.execute(select(ScannerExecution).where(ScannerExecution.scan_id == scan.id).order_by(ScannerExecution.scanner_name))).scalars().all()
    return {**ser(scan), "repository_name": repo.full_name, "executions": [ser(e) for e in execs]}
