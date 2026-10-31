"""Organization integrations configured from the UI: list, save (+verify), test, re-verify, remove."""

from typing import Any, Dict, Optional

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import OrgContext, get_org_context, require_role
from app.integrations import registry
from app.services.audit import audit

router = APIRouter()


class IntegrationIn(BaseModel):
    config: Dict[str, Any] = Field(default_factory=dict)
    secrets: Dict[str, Optional[str]] = Field(default_factory=dict, description="Blank or omitted keeps the stored value")


def _kind(kind: str) -> str:
    if kind not in registry.DEFINITIONS:
        raise HTTPException(404, "Unknown integration")
    return kind


@router.get("")
async def list_integrations(ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    """Status of every integration (no secret values). Visible to all members so the UI can gate features."""
    return [registry.serialize(await registry.resolve(db, ctx.org_id, k)) for k in registry.KINDS]


@router.get("/{kind}")
async def get_integration(kind: str, ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    return registry.serialize(await registry.resolve(db, ctx.org_id, _kind(kind)))


@router.put("/{kind}")
async def save_integration(kind: str, body: IntegrationIn, ctx: OrgContext = Depends(require_role("admin")), db: AsyncSession = Depends(get_db)):
    """Save and immediately verify. The result is stored even when verification fails, so it can be fixed."""
    row = await registry.save(db, ctx.org_id, _kind(kind), body.config, body.secrets, ctx.user)
    await audit(db, "integration.save", org_id=ctx.org_id, user=ctx.user, resource_type="integration", resource_id=row.id,
                details={"kind": kind, "status": row.status, "provider": row.config.get("provider"), "secrets_updated": sorted(k for k, v in body.secrets.items() if v)})
    return registry.serialize(await registry.resolve(db, ctx.org_id, kind))


@router.post("/{kind}/verify")
async def verify_integration(kind: str, body: Optional[IntegrationIn] = Body(default=None), ctx: OrgContext = Depends(require_role("admin")),
                             db: AsyncSession = Depends(get_db)):
    """With a body: test the draft without saving. Without: re-verify the stored configuration and record the result."""
    _kind(kind)
    if body is not None and (body.config or body.secrets):
        ok, message, details = await registry.test_unsaved(db, ctx.org_id, kind, body.config, body.secrets)
        return {"ok": ok, "status": "ok" if ok else "error", "message": message, "details": details, "saved": False}
    r = await registry.resolve(db, ctx.org_id, kind)
    if r.source == "organization":
        await registry.verify_row(r.row)
        await audit(db, "integration.verify", org_id=ctx.org_id, user=ctx.user, resource_type="integration", resource_id=r.row.id,
                    details={"kind": kind, "status": r.row.status})
        await db.flush()
        return {"ok": r.row.status == "ok", "status": r.row.status, "message": r.row.status_message, "details": r.row.details, "saved": True}
    if r.source == "environment":
        ok, message, details = await registry.verify(kind, r.config, r.secrets)
        return {"ok": ok, "status": "ok" if ok else "error", "message": message, "details": details, "saved": False}
    raise registry.IntegrationRequired(kind)


@router.delete("/{kind}")
async def delete_integration(kind: str, ctx: OrgContext = Depends(require_role("admin")), db: AsyncSession = Depends(get_db)):
    r = await registry.resolve(db, ctx.org_id, _kind(kind))
    if r.source != "organization":
        raise HTTPException(404, "Not configured for this organization")
    await db.delete(r.row)
    await audit(db, "integration.delete", org_id=ctx.org_id, user=ctx.user, resource_type="integration", resource_id=r.row.id, details={"kind": kind})
    return {"ok": True}
