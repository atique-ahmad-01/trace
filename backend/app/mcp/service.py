"""
MCP integration layer.

- Servers can only be registered from an allowlisted registry (built-in TRACE server,
  known community servers) or as remote streamable-HTTP URLs added by an org admin.
  Arbitrary local commands are never accepted from the API.
- Tool discovery stores schemas; every tool starts denied unless it is a built-in
  read-only tool. Admins toggle allow / requires_approval / allowed agents.
- Execution enforces: tool allowed, agent permitted, approval for sensitive tools,
  timeouts; every call is logged to mcp_tool_executions.
"""

import asyncio
import json
import sys
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import BACKEND_DIR, settings
from app.db.models import MCPIntegration, MCPTool, MCPToolExecution

BUILTIN_NAME = "trace-security"

# Read-only built-in tools and the agents allowed to use them by default.
BUILTIN_DEFAULTS = {
    "osv_query_package": {"agents": ["vulnerability_research", "verification"], "sensitivity": "network"},
    "osv_get_vulnerability": {"agents": ["vulnerability_research"], "sensitivity": "network"},
    "nvd_get_cve": {"agents": ["vulnerability_research"], "sensitivity": "network"},
    "cisa_kev_check": {"agents": ["vulnerability_research", "risk_assessment"], "sensitivity": "network"},
    "cwe_lookup": {"agents": ["code_analysis", "vulnerability_research"], "sensitivity": "network"},
    "list_files": {"agents": ["code_analysis"], "sensitivity": "read"},
    "read_file": {"agents": ["code_analysis", "remediation"], "sensitivity": "read"},
    "search_code": {"agents": ["code_analysis"], "sensitivity": "read"},
    "gitleaks_scan": {"agents": ["verification"], "sensitivity": "read"},
}

# Allowlisted server templates. Only these may be launched as local processes.
REGISTRY: Dict[str, Dict[str, Any]] = {
    BUILTIN_NAME: {
        "description": "Built-in TRACE security tools: OSV, NVD, CISA KEV, CWE, sandboxed file inspection, Gitleaks.",
        "transport": "stdio",
        "command": [sys.executable, "-m", "app.mcp_servers.trace_security"],
        "builtin": True,
    },
    "github": {
        "description": "Official GitHub MCP server (requires Docker and a GitHub token credential).",
        "transport": "stdio",
        "command": ["docker", "run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN", "ghcr.io/github/github-mcp-server"],
        "builtin": False,
        "requires_credential": "github_token",
    },
}


class MCPPermissionError(Exception):
    pass


def _server_env(root: Optional[str]) -> Dict[str, str]:
    import os

    env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG", "SSL_CERT_FILE", "HTTPS_PROXY", "NO_PROXY")}
    env.update({"TRACE_MCP_ROOT": root or settings.WORK_DIR, "TRACE_TOOLS_DIR": settings.TOOLS_DIR, "PYTHONPATH": str(BACKEND_DIR)})
    return env


@asynccontextmanager
async def _session(integ: MCPIntegration, root: Optional[str] = None, credential: Optional[str] = None):
    from mcp import ClientSession, StdioServerParameters

    if integ.transport == "stdio":
        from mcp.client.stdio import stdio_client

        tmpl = REGISTRY.get(integ.name)
        if not tmpl or tmpl["command"] != integ.command:
            raise MCPPermissionError("stdio server command is not in the allowlisted registry")
        env = _server_env(root)
        if credential:
            env["GITHUB_PERSONAL_ACCESS_TOKEN"] = credential
        params = StdioServerParameters(command=integ.command[0], args=integ.command[1:], env=env, cwd=str(BACKEND_DIR))
        async with stdio_client(params) as (r, w):
            async with ClientSession(r, w) as s:
                await s.initialize()
                yield s
    elif integ.transport == "streamable_http":
        from mcp.client.streamable_http import streamablehttp_client

        if not (integ.url or "").startswith("https://") and "localhost" not in (integ.url or ""):
            raise MCPPermissionError("remote MCP servers must use https")
        async with streamablehttp_client(integ.url) as (r, w, _):
            async with ClientSession(r, w) as s:
                await s.initialize()
                yield s
    else:
        raise MCPPermissionError(f"unsupported transport {integ.transport}")


async def ensure_builtin(db: AsyncSession, org_id: uuid.UUID) -> MCPIntegration:
    integ = (await db.execute(select(MCPIntegration).where(MCPIntegration.organization_id == org_id, MCPIntegration.name == BUILTIN_NAME))).scalar_one_or_none()
    tmpl = REGISTRY[BUILTIN_NAME]
    if not integ:
        integ = MCPIntegration(organization_id=org_id, name=BUILTIN_NAME, description=tmpl["description"], transport="stdio",
                               command=tmpl["command"], is_builtin=True)
        db.add(integ)
        await db.flush()
    elif integ.command != tmpl["command"]:
        integ.command = tmpl["command"]  # interpreter path can change between environments
    return integ


async def discover(db: AsyncSession, integ: MCPIntegration, credential: Optional[str] = None) -> List[MCPTool]:
    try:
        async with asyncio.timeout(settings.MCP_TOOL_TIMEOUT):
            async with _session(integ, credential=credential) as s:
                listed = (await s.list_tools()).tools
    except Exception as e:  # noqa: BLE001
        integ.status, integ.status_detail = "error", f"{type(e).__name__}: {e}"[:500]
        await db.flush()
        raise
    existing = {t.name: t for t in (await db.execute(select(MCPTool).where(MCPTool.integration_id == integ.id))).scalars()}
    out = []
    for t in listed:
        row = existing.get(t.name)
        if not row:
            defaults = BUILTIN_DEFAULTS.get(t.name) if integ.is_builtin else None
            row = MCPTool(integration_id=integ.id, name=t.name, is_allowed=bool(defaults),
                          allowed_agents=(defaults or {}).get("agents", []), sensitivity=(defaults or {}).get("sensitivity", "write"),
                          requires_approval=not integ.is_builtin)
            db.add(row)
        row.description, row.input_schema = t.description, t.inputSchema
        out.append(row)
    integ.status, integ.status_detail, integ.last_connected_at = "connected", f"{len(listed)} tools", datetime.now(timezone.utc)
    await db.flush()
    return out


async def call_tool(db: AsyncSession, org_id: uuid.UUID, tool: MCPTool, arguments: Dict[str, Any], *, invoked_by: str,
                    agent: Optional[str] = None, approved: bool = False, root: Optional[str] = None,
                    investigation_id: Optional[uuid.UUID] = None) -> Dict[str, Any]:
    integ = await db.get(MCPIntegration, tool.integration_id)
    if integ.organization_id != org_id:
        raise MCPPermissionError("tool belongs to another organization")
    log = MCPToolExecution(organization_id=org_id, tool_id=tool.id, invoked_by=invoked_by, arguments=_redact_args(arguments),
                           investigation_id=investigation_id)
    db.add(log)

    denial = None
    if not integ.is_active:
        denial = "integration is disabled"
    elif not tool.is_allowed:
        denial = f"tool '{tool.name}' is not on the allowlist"
    elif agent and agent not in (tool.allowed_agents or []):
        denial = f"agent '{agent}' is not permitted to use '{tool.name}'"
    elif tool.requires_approval and not approved:
        denial = f"tool '{tool.name}' requires explicit human approval"
    if denial:
        log.status, log.error_message = "denied", denial
        await db.flush()
        raise MCPPermissionError(denial)

    t = time.monotonic()
    try:
        async with asyncio.timeout(settings.MCP_TOOL_TIMEOUT):
            async with _session(integ, root=root) as s:
                res = await s.call_tool(tool.name, arguments)
        content = []
        for c in res.content:
            text = getattr(c, "text", None)
            if text is not None:
                try:
                    content.append(json.loads(text))
                except json.JSONDecodeError:
                    content.append(text)
        structured = getattr(res, "structuredContent", None)
        result = structured.get("result", structured) if isinstance(structured, dict) else (content[0] if len(content) == 1 else content)
        log.status = "error" if res.isError else "success"
        log.result_preview = json.dumps(result, default=str)[:2000]
        if res.isError:
            log.error_message = str(result)[:1000]
        return {"ok": not res.isError, "result": result}
    except TimeoutError:
        log.status, log.error_message = "timeout", f"exceeded {settings.MCP_TOOL_TIMEOUT}s"
        return {"ok": False, "error": log.error_message}
    except Exception as e:  # noqa: BLE001
        logger.warning(f"MCP call {tool.name} failed: {e}")
        log.status, log.error_message = "error", f"{type(e).__name__}: {e}"[:1000]
        return {"ok": False, "error": log.error_message}
    finally:
        log.duration_ms = int((time.monotonic() - t) * 1000)
        await db.flush()


def _redact_args(args: Dict[str, Any]) -> Dict[str, Any]:
    return {k: ("[REDACTED]" if any(s in k.lower() for s in ("token", "secret", "password", "key")) else v) for k, v in (args or {}).items()}


async def get_tool(db: AsyncSession, org_id: uuid.UUID, name: str, integration_name: str = BUILTIN_NAME) -> Optional[MCPTool]:
    return (await db.execute(
        select(MCPTool).join(MCPIntegration).where(MCPIntegration.organization_id == org_id, MCPIntegration.name == integration_name, MCPTool.name == name)
    )).scalar_one_or_none()
