"""
Investigation service: wires the LangGraph workflow to the database, intelligence,
RAG, MCP tools and an authorized repository snapshot, and persists results/traces.
"""

import asyncio
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from loguru import logger
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.graph import Toolbox, get_graph
from app.core import database
from app.core.config import settings
from app.db.models import AgentEvent, AgentInvestigation, Finding, FindingStatus, RemediationProposal, Repository
from app.intel import service as intel
from app.llm.provider import get_provider
from app.mcp import service as mcp
from app.rag import engine as rag
from app.services import jobs, patching, snapshot


def finding_to_dict(f: Finding) -> Dict[str, Any]:
    keys = ["id", "title", "description", "finding_type", "scanner_name", "detected_by", "rule_id", "severity", "vuln_id", "aliases",
            "cwe_ids", "cvss_score", "file_path", "start_line", "end_line", "code_snippet", "package_name", "package_ecosystem",
            "installed_version", "fixed_version", "references", "commit_sha"]
    d = {k: getattr(f, k) for k in keys}
    d["id"] = str(f.id)
    return d


async def create_investigation(db: AsyncSession, finding: Finding, user_id=None, mode: str = "agentic_rag",
                               provider: Optional[str] = None, model: Optional[str] = None) -> AgentInvestigation:
    p = get_provider(provider, model)
    inv = AgentInvestigation(organization_id=finding.organization_id, finding_id=finding.id, requested_by=user_id, status="queued",
                             mode=mode, model=f"{p.name}:{p.model}" if p.model else p.name)
    db.add(inv)
    await db.flush()
    jobs.enqueue("app.agents.service.run_investigation", str(inv.id), provider or "", model or "")
    return inv


class _Emitter:
    def __init__(self, inv_id: uuid.UUID):
        self.inv_id = inv_id
        self.seq = 0
        self.lock = asyncio.Lock()

    async def __call__(self, agent: str, event_type: str, message: str, data: Optional[dict] = None, duration_ms: Optional[int] = None):
        async with self.lock:
            self.seq += 1
            async with database.async_session_maker() as s:
                s.add(AgentEvent(investigation_id=self.inv_id, sequence=self.seq, agent_name=agent, event_type=event_type,
                                 message=(message or "")[:2000], data=data or {}, duration_ms=duration_ms))
                await s.commit()


async def run_investigation(inv_id: str, provider: str = "", model: str = "") -> None:
    iid = uuid.UUID(str(inv_id))
    async with database.async_session_maker() as db:
        inv = await db.get(AgentInvestigation, iid)
        finding = await db.get(Finding, inv.finding_id)
        repo = await db.get(Repository, finding.repository_id)
        inv.status, inv.started_at = "running", datetime.now(timezone.utc)
        await mcp.ensure_builtin(db, inv.organization_id)
        await db.commit()
        org_id = inv.organization_id

    emit = _Emitter(iid)
    llm = get_provider(provider or None, model or None)
    t0 = time.monotonic()
    snap_cm, snap = None, None
    try:
        # Authorized snapshot for code inspection / manifest patching (same access path as scans).
        try:
            token = None
            async with database.async_session_maker() as db:
                if repo.provider == "github":
                    from app.integrations.github import token_for_repo

                    token = await token_for_repo(db, repo)
            source = (repo.extra or {}).get("local_path") if repo.provider == "local" else repo.clone_url
            commit = finding.commit_sha if repo.provider != "local" and finding.commit_sha and not finding.commit_sha.startswith("local-") else None
            snap_cm = snapshot.checkout(repo.provider, source, branch=repo.default_branch, commit=commit, token=token)
            snap = await asyncio.to_thread(snap_cm.__enter__)
            await emit("supervisor", "tool_call", f"Checked out snapshot {snap.commit_sha[:12]} for code inspection", {"commit": snap.commit_sha})
        except Exception as e:  # noqa: BLE001
            snap_cm = None
            await emit("supervisor", "error", f"Repository snapshot unavailable; code tools disabled: {e}")

        async def intel_lookup(vid, aliases):
            async with database.async_session_maker() as s:
                rec = await intel.lookup(s, vid, aliases)
                d = intel.record_to_dict(rec)
                await s.commit()
                return d

        async def retrieve(query, exact_ids=None, filters=None):
            async with database.async_session_maker() as s:
                return await rag.retrieve(s, query, org_id=org_id, exact_ids=exact_ids, filters=filters)

        async def mcp_call(agent, tool_name, args):
            async with database.async_session_maker() as s:
                tool = await mcp.get_tool(s, org_id, tool_name)
                if not tool:
                    integ = await mcp.ensure_builtin(s, org_id)
                    await mcp.discover(s, integ)
                    tool = await mcp.get_tool(s, org_id, tool_name)
                if tool and tool.sensitivity == "read" and not snap:
                    return {"ok": False, "error": "no repository snapshot available"}
                try:
                    res = await mcp.call_tool(s, org_id, tool, args, invoked_by=f"agent:{agent}", agent=agent,
                                              root=snap.path if snap else None, investigation_id=iid)
                except mcp.MCPPermissionError as e:
                    res = {"ok": False, "error": f"denied: {e}"}
                await s.commit()
            await emit(agent, "tool_call", f"MCP {tool_name} → {'ok' if res.get('ok') else res.get('error')}", {"arguments": args})
            return res

        async def manifest_reader(f):
            files = {}
            if not snap:
                return files
            for rel in set(patching.manifest_candidates(f.get("file_path"))):
                p = os.path.realpath(os.path.join(snap.path, rel))
                if p.startswith(os.path.realpath(snap.path) + os.sep) and os.path.isfile(p):
                    with open(p, "r", encoding="utf-8", errors="replace") as fh:
                        files[rel] = fh.read()
            return files

        tb = Toolbox(llm=llm, emit=emit, intel_lookup=intel_lookup, retrieve=retrieve, mcp_call=mcp_call,
                     manifest_reader=manifest_reader, patcher=patching.make_patch)
        state = await get_graph().ainvoke(
            {"finding": finding_to_dict(finding), "mode": inv.mode, "evidence": [], "completed": [], "failed": [], "attempts": {},
             "tokens_in": 0, "tokens_out": 0, "injection_signals": []},
            {"configurable": {"toolbox": tb}, "recursion_limit": 40},
        )
        await _persist(iid, state, int((time.monotonic() - t0) * 1000), snap.commit_sha if snap else None)
    except Exception as e:  # noqa: BLE001
        logger.exception("investigation failed")
        async with database.async_session_maker() as db:
            inv = await db.get(AgentInvestigation, iid)
            inv.status, inv.error_message, inv.completed_at = "failed", f"{type(e).__name__}: {e}"[:1000], datetime.now(timezone.utc)
            await db.commit()
        await emit("supervisor", "error", f"Investigation failed: {e}")
    finally:
        if snap_cm is not None:
            await asyncio.to_thread(snap_cm.__exit__, None, None, None)


async def _persist(iid: uuid.UUID, state: Dict[str, Any], latency_ms: int, base_commit: Optional[str]) -> None:
    async with database.async_session_maker() as db:
        inv = await db.get(AgentInvestigation, iid)
        finding = await db.get(Finding, inv.finding_id)
        keys = {"vulnerability_research": "research", "code_analysis": "code_result", "risk_assessment": "risk", "remediation": "remediation_result"}
        without_model = [a for a, k in keys.items() if state.get(k) and not state[k].get("model_used")]
        failed = state.get("failed") or []
        if not state.get("completed"):
            inv.status = "failed"
        elif failed or without_model:
            inv.status = "partial"
        else:
            inv.status = "completed"
        notes = []
        if failed:
            notes.append(f"Agents failed: {', '.join(failed)}.")
        if without_model:
            notes.append(f"No model output for: {', '.join(without_model)} — those sections contain structured evidence and deterministic analysis only.")
        inv.error_message = " ".join(notes) or None
        inv.summary = state.get("summary")
        inv.research, inv.code_analysis = state.get("research"), state.get("code_result")
        inv.risk_assessment, inv.remediation = state.get("risk"), state.get("remediation_result")
        inv.evidence = state.get("evidence") or []
        inv.citations = [{"id": e["citation_id"], "title": e["title"], "url": e.get("url"), "source_type": e["source_type"], "kind": e["kind"]}
                         for e in inv.evidence]
        inv.tokens_in, inv.tokens_out, inv.latency_ms = state.get("tokens_in", 0), state.get("tokens_out", 0), latency_ms
        inv.completed_at = datetime.now(timezone.utc)

        risk = state.get("risk") or {}
        if risk:
            finding.risk_score, finding.priority = risk.get("risk_score"), risk.get("priority")

        rem = state.get("remediation_result") or {}
        if rem and (rem.get("patch") or rem.get("steps")):
            r = state.get("research") or {}
            db.add(RemediationProposal(
                organization_id=finding.organization_id, finding_id=finding.id, investigation_id=inv.id, proposed_by="agent:remediation",
                title=(f"Upgrade {finding.package_name} to {rem['target_version']}" if rem.get("target_version")
                       else rem.get("fix_summary") or f"Remediate: {finding.title}")[:500],
                root_cause=rem.get("root_cause") or r.get("model_summary"),
                description="\n".join(f"- {s}" for s in rem.get("steps") or []), remediation_type=rem.get("type"), patch=rem.get("patch"),
                files_changed=rem.get("files_changed") or [], side_effects=rem.get("side_effects") or rem.get("patch_note"),
                evidence_sufficient=bool(rem.get("evidence_sufficient")), confidence=rem.get("confidence"), base_commit=base_commit,
            ))
        await db.commit()


async def investigation_stats(db: AsyncSession, org_id) -> Dict[str, Any]:
    rows = (await db.execute(select(AgentInvestigation.status, func.count()).where(AgentInvestigation.organization_id == org_id)
                             .group_by(AgentInvestigation.status))).all()
    return {s: c for s, c in rows}
