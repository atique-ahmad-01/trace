"""
GitHub integration.

Authorization order for repository access:
1. GitHub App installation token (GITHUB_APP_ID + private key, repository linked to an installation)
2. The organization's GitHub integration (encrypted PAT set in Settings -> Integrations)
3. A legacy "github_token" credential, then GITHUB_TOKEN when env fallback is enabled
4. Anonymous (public repositories only)
"""

import time
import uuid
from typing import Any, Dict, List, Optional

import httpx
import jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import decrypt_secret
from app.db.models import Credential, GitHubInstallation, Repository


class GitHubError(Exception):
    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status = status


def app_configured() -> bool:
    return bool(settings.GITHUB_APP_ID and settings.GITHUB_APP_PRIVATE_KEY_PATH)


def _app_jwt() -> str:
    with open(settings.GITHUB_APP_PRIVATE_KEY_PATH, "r") as fh:
        key = fh.read()
    now = int(time.time())
    return jwt.encode({"iat": now - 60, "exp": now + 540, "iss": settings.GITHUB_APP_ID}, key, algorithm="RS256")


def _headers(token: Optional[str] = None, bearer: bool = False) -> Dict[str, str]:
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "TRACE"}
    if token:
        h["Authorization"] = f"Bearer {token}" if bearer else f"token {token}"
    return h


async def _request(method: str, path: str, token: Optional[str] = None, bearer: bool = False, **kw) -> Any:
    async with httpx.AsyncClient(base_url=settings.GITHUB_API_URL, timeout=30) as c:
        r = await c.request(method, path, headers=_headers(token, bearer), **kw)
    if r.status_code >= 400:
        try:
            msg = r.json().get("message", r.text)
        except ValueError:
            msg = r.text
        raise GitHubError(f"GitHub API {method} {path} -> {r.status_code}: {msg[:300]}", r.status_code)
    return r.json() if r.content else None


async def installation_token(installation_id: str) -> str:
    if not app_configured():
        raise GitHubError("GitHub App is not configured (GITHUB_APP_ID / GITHUB_APP_PRIVATE_KEY_PATH)")
    data = await _request("POST", f"/app/installations/{installation_id}/access_tokens", token=_app_jwt(), bearer=True)
    return data["token"]


async def get_installation(installation_id: str) -> Dict[str, Any]:
    return await _request("GET", f"/app/installations/{installation_id}", token=_app_jwt(), bearer=True)


async def org_token(db: AsyncSession, org_id: uuid.UUID) -> Optional[str]:
    from app.integrations import registry

    r = await registry.resolve(db, org_id, "github")
    if r.source == "organization":
        return r.secrets.get("token") if r.ready else None
    cred = (
        await db.execute(select(Credential).where(Credential.organization_id == org_id, Credential.kind == "github_token"))
    ).scalar_one_or_none()
    if cred:
        return decrypt_secret(cred.encrypted_value)
    return r.secrets.get("token")  # environment fallback, if enabled


async def token_for_repo(db: AsyncSession, repo: Repository) -> Optional[str]:
    if repo.installation_id and app_configured():
        inst = await db.get(GitHubInstallation, repo.installation_id)
        if inst and not inst.suspended:
            return await installation_token(inst.installation_id)
    return await org_token(db, repo.organization_id)


async def list_accessible_repos(db: AsyncSession, org_id: uuid.UUID) -> List[Dict[str, Any]]:
    """Repositories visible through installations or the stored token."""
    repos: List[Dict[str, Any]] = []
    if app_configured():
        insts = (await db.execute(select(GitHubInstallation).where(GitHubInstallation.organization_id == org_id))).scalars().all()
        for inst in insts:
            tok = await installation_token(inst.installation_id)
            data = await _request("GET", "/installation/repositories", token=tok, params={"per_page": 100})
            for r in data.get("repositories", []):
                repos.append({**_repo_summary(r), "installation_id": str(inst.id)})
    if not repos:
        tok = await org_token(db, org_id)
        if not tok:
            raise GitHubError("No GitHub App installation or token configured")
        data = await _request("GET", "/user/repos", token=tok, params={"per_page": 100, "sort": "updated"})
        repos = [_repo_summary(r) for r in data]
    return repos


def _repo_summary(r: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "github_id": str(r["id"]),
        "name": r["name"],
        "full_name": r["full_name"],
        "description": r.get("description"),
        "clone_url": r["clone_url"],
        "html_url": r["html_url"],
        "default_branch": r.get("default_branch") or "main",
        "language": r.get("language"),
        "is_private": r.get("private", False),
    }


async def get_repo(full_name: str, token: Optional[str]) -> Dict[str, Any]:
    return _repo_summary(await _request("GET", f"/repos/{full_name}", token=token))


async def list_branches(full_name: str, token: Optional[str]) -> List[Dict[str, Any]]:
    data = await _request("GET", f"/repos/{full_name}/branches", token=token, params={"per_page": 100})
    return [{"name": b["name"], "sha": b["commit"]["sha"]} for b in data]


async def create_pull_request(
    full_name: str, token: str, base: str, branch: str, title: str, body: str, files: Dict[str, str], base_sha: str
) -> Dict[str, Any]:
    """Create a branch with updated file contents via the Git Data API and open a PR (never merged)."""
    import base64

    blobs = []
    for path, content in files.items():
        blob = await _request("POST", f"/repos/{full_name}/git/blobs", token=token,
                              json={"content": base64.b64encode(content.encode()).decode(), "encoding": "base64"})
        blobs.append({"path": path, "mode": "100644", "type": "blob", "sha": blob["sha"]})
    base_commit = await _request("GET", f"/repos/{full_name}/git/commits/{base_sha}", token=token)
    tree = await _request("POST", f"/repos/{full_name}/git/trees", token=token, json={"base_tree": base_commit["tree"]["sha"], "tree": blobs})
    commit = await _request("POST", f"/repos/{full_name}/git/commits", token=token, json={"message": title, "tree": tree["sha"], "parents": [base_sha]})
    await _request("POST", f"/repos/{full_name}/git/refs", token=token, json={"ref": f"refs/heads/{branch}", "sha": commit["sha"]})
    return await _request("POST", f"/repos/{full_name}/pulls", token=token, json={"title": title, "head": branch, "base": base, "body": body, "maintainer_can_modify": True})


async def get_file(full_name: str, path: str, ref: str, token: Optional[str]) -> str:
    import base64

    data = await _request("GET", f"/repos/{full_name}/contents/{path}", token=token, params={"ref": ref})
    return base64.b64decode(data["content"]).decode("utf-8", "replace")


async def advisories_for_cve(cve_id: str, token: Optional[str]) -> List[Dict[str, Any]]:
    return await _request("GET", "/advisories", token=token, params={"cve_id": cve_id, "per_page": 5})
