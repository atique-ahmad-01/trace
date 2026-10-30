"""Repository management and GitHub integration endpoints."""

import os
import re
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.common import Page, get_owned, iso, paginate, ser
from app.core.config import BACKEND_DIR, settings
from app.core.database import get_db
from app.core.deps import OrgContext, get_org_context, require_role
from app.db.models import Finding, GitHubInstallation, Repository, RepositoryCommit, Scan
from app.integrations import github
from app.services.audit import audit

router = APIRouter()


async def _repo_out(db: AsyncSession, r: Repository) -> dict:
    counts = dict((await db.execute(select(Finding.severity, func.count()).where(Finding.repository_id == r.id, Finding.status == "OPEN")
                                    .group_by(Finding.severity))).all())
    return {**ser(r), "open_findings": sum(counts.values()), "severity_counts": counts}


@router.get("")
async def list_repositories(q: Optional[str] = None, page: Page = Depends(), ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    stmt = select(Repository).where(Repository.organization_id == ctx.org_id)
    if q:
        stmt = stmt.where(Repository.full_name.ilike(f"%{q}%"))
    res = await paginate(db, stmt.order_by(Repository.created_at.desc()), page, mapper=lambda r: r)
    res["items"] = [await _repo_out(db, r) for r in res["items"]]
    return res


class RepoIn(BaseModel):
    provider: str = Field(default="github", pattern="^(github|git|local)$")
    full_name: Optional[str] = Field(default=None, max_length=300, description="owner/name for GitHub")
    clone_url: Optional[str] = Field(default=None, max_length=1000)
    local_path: Optional[str] = Field(default=None, description="Fixture path under backend/tests/fixtures (demo/test mode)")
    default_branch: Optional[str] = Field(default=None, max_length=200)
    installation_id: Optional[uuid.UUID] = None


@router.post("", status_code=201)
async def create_repository(body: RepoIn, ctx: OrgContext = Depends(require_role("member")), db: AsyncSession = Depends(get_db)):
    data: dict = {"provider": body.provider}
    if body.provider == "github":
        name = body.full_name or ""
        m = re.match(r"^(?:https://github\.com/)?([\w.-]+/[\w.-]+?)(?:\.git)?/?$", name or (body.clone_url or ""))
        if not m:
            raise HTTPException(422, "Provide full_name as owner/repo or a https://github.com/owner/repo URL")
        full = m.group(1)
        token = None
        if body.installation_id:
            inst = await get_owned(db, GitHubInstallation, body.installation_id, ctx.org_id, "Installation")
            token = await github.installation_token(inst.installation_id)
        else:
            token = await github.org_token(db, ctx.org_id)
        try:
            meta = await github.get_repo(full, token)
        except github.GitHubError as e:
            raise HTTPException(e.status if e.status in (401, 403, 404) else 502, str(e))
        data.update(meta)
        data["installation_id"] = body.installation_id
    elif body.provider == "git":
        if not (body.clone_url or "").startswith("https://"):
            raise HTTPException(422, "clone_url must be https://")
        name = body.clone_url.rstrip("/").removesuffix(".git").split("/")[-1]
        data.update({"name": name, "full_name": body.full_name or body.clone_url.removeprefix("https://").removesuffix(".git"), "clone_url": body.clone_url})
    else:
        path = os.path.realpath(os.path.join(BACKEND_DIR, "tests", "fixtures", body.local_path or ""))
        from app.services.snapshot import _local_path_allowed

        if not body.local_path or not _local_path_allowed(path) or not os.path.isdir(path):
            raise HTTPException(422, "local_path must be a fixture directory under backend/tests/fixtures")
        name = os.path.basename(path)
        data.update({"name": name, "full_name": f"local/{name}", "extra": {"local_path": path}, "is_demo": True,
                     "description": "Local fixture repository (test/demo mode)"})
    if body.default_branch:
        data["default_branch"] = body.default_branch
    if (await db.execute(select(Repository).where(Repository.organization_id == ctx.org_id, Repository.full_name == data["full_name"]))).scalar_one_or_none():
        raise HTTPException(409, "Repository already connected")
    repo = Repository(organization_id=ctx.org_id, **data)
    db.add(repo)
    await db.flush()
    await audit(db, "repository.connect", org_id=ctx.org_id, user=ctx.user, resource_type="repository", resource_id=repo.id,
                details={"full_name": repo.full_name, "provider": repo.provider})
    return await _repo_out(db, repo)


@router.get("/fixtures")
async def list_fixtures(ctx: OrgContext = Depends(get_org_context)):
    root = BACKEND_DIR / "tests" / "fixtures"
    return [d for d in sorted(os.listdir(root)) if (root / d).is_dir()]


@router.get("/github/available")
async def github_available(ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    try:
        repos = await github.list_accessible_repos(db, ctx.org_id)
    except github.GitHubError as e:
        return {"configured": False, "error": str(e), "repositories": [], "app_configured": github.app_configured(),
                "install_url": f"https://github.com/apps/{settings.GITHUB_APP_SLUG}/installations/new" if settings.GITHUB_APP_SLUG else None}
    connected = set((await db.execute(select(Repository.full_name).where(Repository.organization_id == ctx.org_id))).scalars())
    return {"configured": True, "app_configured": github.app_configured(), "repositories": [{**r, "connected": r["full_name"] in connected} for r in repos]}


class InstallationIn(BaseModel):
    installation_id: str = Field(pattern=r"^\d+$")


@router.post("/github/installations", status_code=201)
async def link_installation(body: InstallationIn, ctx: OrgContext = Depends(require_role("admin")), db: AsyncSession = Depends(get_db)):
    """Link a GitHub App installation (from the post-install redirect) after verifying it with the GitHub API."""
    try:
        info = await github.get_installation(body.installation_id)
    except (github.GitHubError, OSError) as e:
        raise HTTPException(400, f"Could not verify installation: {e}")
    if (await db.execute(select(GitHubInstallation).where(GitHubInstallation.installation_id == body.installation_id))).scalar_one_or_none():
        raise HTTPException(409, "Installation already linked")
    inst = GitHubInstallation(organization_id=ctx.org_id, installation_id=body.installation_id, account_login=info["account"]["login"],
                              account_type=info["account"]["type"], permissions=info.get("permissions", {}),
                              repository_selection=info.get("repository_selection"))
    db.add(inst)
    await audit(db, "github.installation_linked", org_id=ctx.org_id, user=ctx.user, details={"installation_id": body.installation_id})
    await db.flush()
    return ser(inst)


@router.get("/{repo_id}")
async def get_repository(repo_id: uuid.UUID, ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    repo = await get_owned(db, Repository, repo_id, ctx.org_id, "Repository")
    out = await _repo_out(db, repo)
    scans = (await db.execute(select(Scan).where(Scan.repository_id == repo.id).order_by(Scan.created_at.desc()).limit(30))).scalars().all()
    commits = (await db.execute(select(RepositoryCommit).where(RepositoryCommit.repository_id == repo.id).order_by(RepositoryCommit.created_at.desc()).limit(20))).scalars().all()
    trend = [{"date": iso(s.completed_at or s.created_at), "critical": s.critical_count, "high": s.high_count,
              "medium": s.medium_count, "low": s.low_count, "total": s.total_findings} for s in reversed(scans) if s.status in ("COMPLETED", "PARTIAL")]
    return {**out, "scans": [ser(s, exclude=("log",)) for s in scans], "commits": [ser(c) for c in commits], "trend": trend}


class RepoUpdate(BaseModel):
    default_branch: Optional[str] = Field(default=None, max_length=200)
    is_active: Optional[bool] = None


@router.patch("/{repo_id}")
async def update_repository(repo_id: uuid.UUID, body: RepoUpdate, ctx: OrgContext = Depends(require_role("member")), db: AsyncSession = Depends(get_db)):
    repo = await get_owned(db, Repository, repo_id, ctx.org_id, "Repository")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(repo, k, v)
    await audit(db, "repository.update", org_id=ctx.org_id, user=ctx.user, resource_type="repository", resource_id=repo.id, details=body.model_dump(exclude_none=True))
    return ser(repo)


@router.delete("/{repo_id}")
async def delete_repository(repo_id: uuid.UUID, ctx: OrgContext = Depends(require_role("admin")), db: AsyncSession = Depends(get_db)):
    repo = await get_owned(db, Repository, repo_id, ctx.org_id, "Repository")
    await db.delete(repo)
    await audit(db, "repository.delete", org_id=ctx.org_id, user=ctx.user, resource_type="repository", resource_id=repo_id, details={"full_name": repo.full_name})
    return {"ok": True}


@router.get("/{repo_id}/branches")
async def branches(repo_id: uuid.UUID, ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)) -> List[dict]:
    repo = await get_owned(db, Repository, repo_id, ctx.org_id, "Repository")
    if repo.provider != "github":
        return [{"name": repo.default_branch, "sha": None}]
    try:
        return await github.list_branches(repo.full_name, await github.token_for_repo(db, repo))
    except github.GitHubError as e:
        raise HTTPException(502, str(e))
