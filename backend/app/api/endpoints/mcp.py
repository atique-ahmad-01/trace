"""MCP integration endpoints: registry, discovery, permissions, execution, logs."""

import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.common import Page, get_owned, paginate, ser
from app.core.database import get_db
from app.core.deps import OrgContext, get_org_context, require_role
from app.db.models import MCPIntegration, MCPTool, MCPToolExecution
from app.integrations.github import org_token
from app.mcp import service as mcp
from app.services.audit import audit

router = APIRouter()


@router.get("/registry")
async def registry(ctx: OrgContext = Depends(get_org_context)):
    return [{"name": k, "description": v["description"], "transport": v["transport"], "builtin": v["builtin"],
             "requires_credential": v.get("requires_credential")} for k, v in mcp.REGISTRY.items()]


@router.get("/integrations")
async def list_integrations(ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    await mcp.ensure_builtin(db, ctx.org_id)
    rows = (await db.execute(select(MCPIntegration).where(MCPIntegration.organization_id == ctx.org_id).order_by(MCPIntegration.name))).scalars().all()
    out = []
    for i in rows:
        tools = (await db.execute(select(MCPTool).where(MCPTool.integration_id == i.id).order_by(MCPTool.name))).scalars().all()
        out.append({**ser(i), "tools": [ser(t) for t in tools]})
    return out


class IntegrationIn(BaseModel):
    name: str = Field(min_length=2, max_length=100, pattern=r"^[\w.-]+$")
    template: Optional[str] = None
    url: Optional[str] = Field(default=None, max_length=1000)
    description: Optional[str] = Field(default=None, max_length=500)


@router.post("/integrations", status_code=201)
async def add_integration(body: IntegrationIn, ctx: OrgContext = Depends(require_role("admin")), db: AsyncSession = Depends(get_db)):
    if body.template:
        tmpl = mcp.REGISTRY.get(body.template)
        if not tmpl:
            raise HTTPException(422, "Unknown registry template")
        integ = MCPIntegration(organization_id=ctx.org_id, name=body.template, description=tmpl["description"], transport=tmpl["transport"],
                               command=tmpl["command"], is_builtin=tmpl["builtin"])
    elif body.url:
        if not body.url.startswith(("https://", "http://localhost", "http://127.0.0.1")):
            raise HTTPException(422, "Remote MCP servers must use https")
        integ = MCPIntegration(organization_id=ctx.org_id, name=body.name, description=body.description, transport="streamable_http", url=body.url)
    else:
        raise HTTPException(422, "Provide a registry template or a remote URL. Arbitrary local commands are not accepted.")
    if (await db.execute(select(MCPIntegration).where(MCPIntegration.organization_id == ctx.org_id, MCPIntegration.name == integ.name))).scalar_one_or_none():
        raise HTTPException(409, "Integration already exists")
    db.add(integ)
    await db.flush()
    await audit(db, "mcp.integration_added", org_id=ctx.org_id, user=ctx.user, resource_type="mcp_integration", resource_id=integ.id,
                details={"name": integ.name, "transport": integ.transport, "url": integ.url})
    return ser(integ)


@router.post("/integrations/{integ_id}/discover")
async def discover(integ_id: uuid.UUID, ctx: OrgContext = Depends(require_role("admin")), db: AsyncSession = Depends(get_db)):
    integ = await get_owned(db, MCPIntegration, integ_id, ctx.org_id, "Integration")
    cred = None
    if mcp.REGISTRY.get(integ.name, {}).get("requires_credential") == "github_token":
        cred = await org_token(db, ctx.org_id)
        if not cred:
            raise HTTPException(400, "This server requires a GitHub token credential (Settings → Credentials)")
    try:
        tools = await mcp.discover(db, integ, credential=cred)
    except mcp.MCPPermissionError as e:
        raise HTTPException(403, str(e))
    except Exception as e:  # noqa: BLE001
        await db.commit()
        raise HTTPException(502, f"Discovery failed: {integ.status_detail or e}")
    await audit(db, "mcp.discover", org_id=ctx.org_id, user=ctx.user, resource_type="mcp_integration", resource_id=integ.id, details={"tools": len(tools)})
    return {"integration": ser(integ), "tools": [ser(t) for t in tools]}


class IntegrationUpdate(BaseModel):
    is_active: bool


@router.patch("/integrations/{integ_id}")
async def update_integration(integ_id: uuid.UUID, body: IntegrationUpdate, ctx: OrgContext = Depends(require_role("admin")), db: AsyncSession = Depends(get_db)):
    integ = await get_owned(db, MCPIntegration, integ_id, ctx.org_id, "Integration")
    integ.is_active = body.is_active
    await audit(db, "mcp.integration_update", org_id=ctx.org_id, user=ctx.user, resource_id=integ.id, details=body.model_dump())
    return ser(integ)


class ToolUpdate(BaseModel):
    is_allowed: Optional[bool] = None
    requires_approval: Optional[bool] = None
    allowed_agents: Optional[List[str]] = None


@router.patch("/tools/{tool_id}")
async def update_tool(tool_id: uuid.UUID, body: ToolUpdate, ctx: OrgContext = Depends(require_role("admin")), db: AsyncSession = Depends(get_db)):
    tool = await db.get(MCPTool, tool_id)
    integ = await db.get(MCPIntegration, tool.integration_id) if tool else None
    if not integ or integ.organization_id != ctx.org_id:
        raise HTTPException(404, "Tool not found")
    from app.agents.api_agents import AGENT_NAMES

    if body.allowed_agents is not None and set(body.allowed_agents) - AGENT_NAMES:
        raise HTTPException(422, f"Unknown agents; valid: {sorted(AGENT_NAMES)}")
    changes = body.model_dump(exclude_none=True)
    for k, v in changes.items():
        setattr(tool, k, v)
    await audit(db, "mcp.tool_permission", org_id=ctx.org_id, user=ctx.user, resource_type="mcp_tool", resource_id=tool.id, details={"tool": tool.name, **changes})
    return ser(tool)


class ExecuteIn(BaseModel):
    arguments: Dict[str, Any] = {}
    approved: bool = False


@router.post("/tools/{tool_id}/execute")
async def execute(tool_id: uuid.UUID, body: ExecuteIn, ctx: OrgContext = Depends(require_role("admin")), db: AsyncSession = Depends(get_db)):
    tool = await db.get(MCPTool, tool_id)
    integ = await db.get(MCPIntegration, tool.integration_id) if tool else None
    if not integ or integ.organization_id != ctx.org_id:
        raise HTTPException(404, "Tool not found")
    if tool.sensitivity == "read" and integ.is_builtin:
        raise HTTPException(400, "Filesystem tools run only inside agent investigations against an authorized repository snapshot")
    try:
        res = await mcp.call_tool(db, ctx.org_id, tool, body.arguments, invoked_by=f"user:{ctx.user.email}", approved=body.approved)
    except mcp.MCPPermissionError as e:
        await db.commit()
        raise HTTPException(403, str(e))
    await audit(db, "mcp.tool_execute", org_id=ctx.org_id, user=ctx.user, resource_type="mcp_tool", resource_id=tool.id,
                details={"tool": tool.name, "ok": res.get("ok"), "approved": body.approved})
    return res


@router.get("/executions")
async def executions(tool_id: Optional[uuid.UUID] = None, status: Optional[str] = None, page: Page = Depends(),
                     ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    q = select(MCPToolExecution, MCPTool.name).join(MCPTool).where(MCPToolExecution.organization_id == ctx.org_id)
    if tool_id:
        q = q.where(MCPToolExecution.tool_id == tool_id)
    if status:
        q = q.where(MCPToolExecution.status == status)
    return await paginate(db, q.order_by(MCPToolExecution.created_at.desc()), page, mapper=lambda e, n: {**ser(e), "tool_name": n})
