"""
GitHub webhooks (push, pull_request, installation).

Signatures (X-Hub-Signature-256) are always verified; requests are rejected when
GITHUB_WEBHOOK_SECRET is unset. Scans are triggered only for repositories that are
connected in TRACE and linked to the sending installation.
"""

import json

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.core.security import verify_github_webhook_signature
from app.db.models import GitHubInstallation, Repository
from app.services.audit import audit

router = APIRouter()


@router.post("/github")
async def github_webhook(request: Request, x_github_event: str = Header(...), x_hub_signature_256: str | None = Header(default=None),
                         x_github_delivery: str | None = Header(default=None), db: AsyncSession = Depends(get_db)):
    if not settings.GITHUB_WEBHOOK_SECRET:
        raise HTTPException(503, "Webhook secret not configured")
    body = await request.body()
    if len(body) > 5 * 1024 * 1024:
        raise HTTPException(413, "Payload too large")
    if not verify_github_webhook_signature(body, x_hub_signature_256, settings.GITHUB_WEBHOOK_SECRET):
        await audit(db, "webhook.invalid_signature", actor="webhook", details={"event": x_github_event, "delivery": x_github_delivery})
        await db.commit()
        raise HTTPException(401, "Invalid signature")
    payload = json.loads(body)
    inst_id = str((payload.get("installation") or {}).get("id") or "")

    if x_github_event == "installation":
        inst = (await db.execute(select(GitHubInstallation).where(GitHubInstallation.installation_id == inst_id))).scalar_one_or_none()
        if inst:
            action = payload.get("action")
            inst.suspended = action in ("suspend", "deleted")
            if action == "new_permissions_accepted":
                inst.permissions = (payload.get("installation") or {}).get("permissions", inst.permissions)
            await audit(db, f"github.installation_{action}", org_id=inst.organization_id, actor="webhook", details={"installation_id": inst_id})
        return {"ok": True, "handled": "installation"}

    if x_github_event == "ping":
        return {"ok": True, "zen": payload.get("zen")}

    if x_github_event not in ("push", "pull_request"):
        return {"ok": True, "ignored": x_github_event}

    full_name = (payload.get("repository") or {}).get("full_name")
    inst = (await db.execute(select(GitHubInstallation).where(GitHubInstallation.installation_id == inst_id))).scalar_one_or_none() if inst_id else None
    if not inst or inst.suspended:
        return {"ok": True, "ignored": "unknown or suspended installation"}
    if (inst.permissions or {}).get("contents") not in ("read", "write"):
        return {"ok": True, "ignored": "installation lacks contents:read permission"}
    repo = (await db.execute(select(Repository).where(Repository.organization_id == inst.organization_id, Repository.full_name == full_name,
                                                      Repository.installation_id == inst.id, Repository.is_active.is_(True)))).scalar_one_or_none()
    if not repo:
        return {"ok": True, "ignored": "repository not connected"}

    from app.api.endpoints.scans import queue_scan

    if x_github_event == "push":
        ref = payload.get("ref", "")
        if not ref.startswith("refs/heads/") or payload.get("deleted"):
            return {"ok": True, "ignored": "non-branch or deleted ref"}
        branch, sha = ref.removeprefix("refs/heads/"), payload.get("after")
        if branch != repo.default_branch:
            return {"ok": True, "ignored": "push to non-default branch"}
        scan = await queue_scan(db, repo, trigger="webhook_push", branch=branch, commit=sha)
    else:
        if payload.get("action") not in ("opened", "synchronize", "reopened"):
            return {"ok": True, "ignored": f"pull_request.{payload.get('action')}"}
        pr = payload["pull_request"]
        if pr["head"]["repo"]["full_name"] != full_name:
            return {"ok": True, "ignored": "fork pull requests are not scanned automatically"}
        scan = await queue_scan(db, repo, trigger="webhook_pr", branch=pr["head"]["ref"], commit=pr["head"]["sha"])
    await audit(db, f"webhook.{x_github_event}", org_id=repo.organization_id, actor="webhook", resource_type="scan", resource_id=scan.id,
                details={"delivery": x_github_delivery, "repository": full_name})
    return {"ok": True, "scan_id": str(scan.id)}
