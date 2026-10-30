"""
LangGraph multi-agent security investigation.

Graph:  START -> supervisor -(route)-> {vulnerability_research | code_analysis | risk_assessment | remediation}
                 each specialist -> supervisor ; supervisor -> finalize -> END

The supervisor owns the shared state, routes explicitly by what is complete, and retries a
failed specialist up to AGENT_MAX_RETRIES before recording the failure and moving on.
Each specialist has a single responsibility and a fixed tool set (enforced again at the MCP layer).
Deterministic facts (CVSS, KEV, fixed versions, risk score) come from structured data, not the model.
"""

import operator
import re
import time
from typing import Annotated, Any, Callable, Dict, List, Optional, TypedDict

from langgraph.graph import END, START, StateGraph

from app.agents.prompts import SECURITY_POLICY, detect_injection, untrusted, valid_citations
from app.llm.provider import BaseProvider, LLMUnavailable
from app.rag.engine import format_evidence_for_prompt

MAX_RETRIES = 2
SPECIALISTS = ["vulnerability_research", "code_analysis", "risk_assessment", "remediation"]


class InvestigationState(TypedDict, total=False):
    finding: Dict[str, Any]
    mode: str
    intel: Optional[Dict[str, Any]]
    evidence: List[Dict[str, Any]]
    research: Optional[Dict[str, Any]]
    code_result: Optional[Dict[str, Any]]
    risk: Optional[Dict[str, Any]]
    remediation_result: Optional[Dict[str, Any]]
    summary: Optional[str]
    completed: Annotated[List[str], operator.add]
    failed: Annotated[List[str], operator.add]
    attempts: Dict[str, int]
    last_error: Optional[str]
    next: str
    tokens_in: Annotated[int, operator.add]
    tokens_out: Annotated[int, operator.add]
    injection_signals: Annotated[List[str], operator.add]


class Toolbox:
    """Capabilities injected per investigation. Each agent receives only the members it needs."""

    def __init__(self, *, llm: BaseProvider, emit: Callable, intel_lookup: Callable, retrieve: Callable, mcp_call: Callable,
                 manifest_reader: Callable, patcher: Callable):
        self.llm, self.emit, self.intel_lookup, self.retrieve = llm, emit, intel_lookup, retrieve
        self.mcp_call, self.manifest_reader, self.patcher = mcp_call, manifest_reader, patcher


def _tb(config) -> Toolbox:
    return config["configurable"]["toolbox"]


async def _llm_json(tb: Toolbox, agent: str, schema_hint: str, user: str) -> tuple[Optional[dict], int, int]:
    t = time.monotonic()
    res = await tb.llm.complete_json(SECURITY_POLICY + f"\n\nYou are the {agent.replace('_', ' ')} agent.\nJSON schema:\n{schema_hint}", user)
    await tb.emit(agent, "llm_call", f"{res.provider}:{res.model} — {res.tokens_in} in / {res.tokens_out} out tokens",
                  {"latency_ms": res.latency_ms, "parsed": res.data is not None}, int((time.monotonic() - t) * 1000))
    return (res.data if isinstance(res.data, dict) else None), res.tokens_in, res.tokens_out


def _finding_brief(f: Dict[str, Any], include_code: bool) -> str:
    parts = [f"Title: {f.get('title')}", f"Type: {f.get('finding_type')}", f"Scanner(s): {', '.join(f.get('detected_by') or [f.get('scanner_name')])}",
             f"Rule: {f.get('rule_id')}", f"Severity (scanner): {f.get('severity')}", f"Identifier: {f.get('vuln_id')} aliases={f.get('aliases')}",
             f"CWE: {f.get('cwe_ids')}", f"Location: {f.get('file_path')}:{f.get('start_line')}"]
    if f.get("package_name"):
        parts.append(f"Package: {f.get('package_name')} {f.get('installed_version')} (ecosystem {f.get('package_ecosystem')}), scanner-reported fix: {f.get('fixed_version')}")
    text = "\n".join(parts) + "\n" + untrusted("scanner_description", f.get("description") or "", 2500)
    if include_code and f.get("code_snippet"):
        text += "\n" + untrusted("code", f["code_snippet"], 3000)
    return text


# --------------------------------------------------------------------------- supervisor


async def supervisor(state: InvestigationState, config) -> Dict[str, Any]:
    tb = _tb(config)
    done, failed = set(state.get("completed", [])), set(state.get("failed", []))
    attempts = dict(state.get("attempts") or {})
    if not state.get("next"):
        await tb.emit("supervisor", "start", f"Investigation plan: {' → '.join(SPECIALISTS)}", {"mode": state.get("mode")})
        f = state["finding"]
        signals = detect_injection(" ".join(str(f.get(k) or "") for k in ("description", "code_snippet", "title")))
        if signals:
            await tb.emit("supervisor", "decision", "Possible prompt-injection content in untrusted finding data; treated strictly as data.",
                          {"signals": signals})
            return {"injection_signals": signals, **(await _route(state, done, failed, attempts, tb))}
    return await _route(state, done, failed, attempts, tb)


async def _route(state, done, failed, attempts, tb) -> Dict[str, Any]:
    for agent in SPECIALISTS:
        if agent in done or agent in failed:
            continue
        n = attempts.get(agent, 0)
        if n > MAX_RETRIES:
            await tb.emit("supervisor", "error", f"{agent} failed after {n} attempts; continuing without it", {"last_error": state.get("last_error")})
            return {"next": "supervisor", "failed": [agent], "attempts": attempts}
        if n > 0:
            await tb.emit("supervisor", "decision", f"Retrying {agent} (attempt {n + 1})", {"last_error": state.get("last_error")})
        attempts[agent] = n + 1
        return {"next": agent, "attempts": attempts}
    return {"next": "finalize", "attempts": attempts}


def route(state: InvestigationState) -> str:
    return state["next"]


# --------------------------------------------------------------------------- specialists


async def vulnerability_research(state: InvestigationState, config) -> Dict[str, Any]:
    tb, f = _tb(config), state["finding"]
    agent = "vulnerability_research"
    await tb.emit(agent, "start", "Researching vulnerability intelligence")
    out: Dict[str, Any] = {"tool_results": []}
    intel = None
    ids = [i for i in [f.get("vuln_id"), *(f.get("aliases") or [])] if i]
    try:
        if f.get("vuln_id"):
            t = time.monotonic()
            intel = await tb.intel_lookup(f["vuln_id"], f.get("aliases") or [])
            src = {k: v.get("status") for k, v in (intel.get("sources") or {}).items()}
            await tb.emit(agent, "tool_call", f"intel.lookup({f['vuln_id']})", {"sources": src, "kev": intel.get("is_known_exploited"),
                                                                               "cvss": intel.get("cvss_score")}, int((time.monotonic() - t) * 1000))
        if f.get("package_name") and f.get("installed_version") and f.get("package_ecosystem") and state.get("mode") == "agentic_rag":
            eco = {"pip": "PyPI", "npm": "npm", "gomod": "Go", "pom": "Maven", "cargo": "crates.io"}.get(f["package_ecosystem"], f["package_ecosystem"])
            r = await tb.mcp_call(agent, "osv_query_package", {"ecosystem": eco, "name": f["package_name"], "version": f["installed_version"]})
            confirmed = None
            if r.get("ok"):
                listed = {i for v in r["result"].get("vulnerabilities", []) for i in [v["id"], *v.get("aliases", [])]}
                confirmed = bool(set(ids) & listed)
            out["version_confirmed_affected"] = confirmed
            out["tool_results"].append({"tool": "mcp:osv_query_package", "ok": r.get("ok"), "confirmed": confirmed, "error": r.get("error")})
    except Exception as e:  # noqa: BLE001
        await tb.emit(agent, "error", f"tool failure: {e}")
        return {"last_error": f"{agent}: {e}"}

    evidence = list(state.get("evidence") or [])
    if state.get("mode") in ("rag", "agentic_rag"):
        q = f"{f.get('title')} {f.get('vuln_id') or ''} {' '.join(f.get('cwe_ids') or [])} {f.get('package_name') or ''} remediation"
        res = await tb.retrieve(q, exact_ids=[f["vuln_id"]] if f.get("vuln_id") else [], filters={})
        evidence = _merge_evidence(evidence, res["evidence"])
        await tb.emit(agent, "evidence", f"Retrieved {len(res['evidence'])} evidence items (hybrid search)",
                      {"diagnostics": res["diagnostics"], "titles": [e["title"] for e in res["evidence"]][:8]})

    schema = '{"summary": str, "affected_versions": str|null, "exploitation_assessment": str, "claims": [{"text": str, "citations": ["S1"]}], "unknowns": [str]}'
    user = _finding_brief(f, include_code=False) + "\n\nStructured intelligence (authoritative):\n" + _intel_brief(intel) + "\n\n" + format_evidence_for_prompt(evidence, 6000)
    data, ti, to = await _safe_llm(tb, agent, schema, user)
    eids = {e["citation_id"] for e in evidence}
    out.update({
        "model_summary": (data or {}).get("summary"),
        "affected_versions": (data or {}).get("affected_versions"),
        "exploitation_assessment": (data or {}).get("exploitation_assessment"),
        "claims": valid_citations((data or {}).get("claims"), eids),
        "unknowns": (data or {}).get("unknowns") or [],
        # deterministic facts — never from the model
        "facts": _intel_facts(intel, f),
        "model_used": data is not None,
    })
    await tb.emit(agent, "complete", (data or {}).get("summary") or "Structured intelligence collected (no model output)",
                  {"facts": out["facts"], "supported_claims": sum(c["supported"] for c in out["claims"]), "total_claims": len(out["claims"])})
    return {"research": out, "intel": intel, "evidence": evidence, "completed": [agent], "tokens_in": ti, "tokens_out": to, "last_error": None}


async def code_analysis(state: InvestigationState, config) -> Dict[str, Any]:
    tb, f = _tb(config), state["finding"]
    agent = "code_analysis"
    await tb.emit(agent, "start", "Analyzing code context and attack paths")
    usages: List[Dict[str, Any]] = []
    context = f.get("code_snippet") or ""
    tool_results = []
    if state.get("mode") == "agentic_rag":
        if f.get("finding_type") == "dependency" and f.get("package_name"):
            names = "|".join(re.escape(n) for n in import_names(f["package_name"]))
            pattern = rf"(^\s*import\s+({names})\b|^\s*from\s+({names})\b|require\(['\"]({names})['\"]\)|from\s+['\"]({names})['\"])"
            r = await tb.mcp_call(agent, "search_code", {"pattern": pattern, "max_results": 20})
            tool_results.append({"tool": "mcp:search_code", "ok": r.get("ok"), "error": r.get("error")})
            if r.get("ok"):
                usages = r["result"] if isinstance(r["result"], list) else []
            await tb.emit(agent, "tool_call", f"search_code for usages of {f['package_name']}: {len(usages)} hits", {"usages": usages[:10]})
        elif f.get("file_path") and f.get("start_line") and f.get("finding_type") != "secret":
            r = await tb.mcp_call(agent, "read_file", {"path": f["file_path"], "start_line": max(1, f["start_line"] - 15), "end_line": f["start_line"] + 15})
            tool_results.append({"tool": "mcp:read_file", "ok": r.get("ok"), "error": r.get("error")})
            if r.get("ok") and isinstance(r["result"], dict):
                context = r["result"].get("content", context)
            await tb.emit(agent, "tool_call", f"read_file {f['file_path']} around line {f['start_line']}", {"ok": r.get("ok")})

    include_code = tb.llm.may_receive_source
    if not include_code:
        await tb.emit(agent, "decision", "Source code withheld from hosted model (ALLOW_SOURCE_TO_HOSTED_LLM=false)")
    schema = ('{"attack_path": str, "data_flow": str, "reachable": "yes"|"no"|"unknown", "exposure": str, '
              '"confirmed": [str], "hypotheses": [str], "affected_components": [str]}')
    user = _finding_brief({**f, "code_snippet": None}, include_code=False)
    if include_code and context:
        user += "\n" + untrusted("code_context", context, 5000)
    if usages and include_code:
        user += "\n" + untrusted("package_usages", "\n".join(f"{u['path']}:{u['line']}: {u['text']}" for u in usages[:20]))
    elif f.get("finding_type") == "dependency" and state.get("mode") == "agentic_rag":
        user += f"\nStatic search found {len(usages)} direct import/require statements for this package."
    data, ti, to = await _safe_llm(tb, agent, schema, user)
    signals = detect_injection(context + " ".join(u.get("text", "") for u in usages))
    out = {
        "attack_path": (data or {}).get("attack_path"), "data_flow": (data or {}).get("data_flow"),
        "reachable": (data or {}).get("reachable", "unknown") if data else ("unknown" if not usages else "yes"),
        "exposure": (data or {}).get("exposure"), "confirmed": (data or {}).get("confirmed") or [],
        "hypotheses": (data or {}).get("hypotheses") or [], "affected_components": (data or {}).get("affected_components") or [],
        "direct_usages": usages[:20], "tool_results": tool_results, "model_used": data is not None,
        "static_reachability": None if f.get("finding_type") != "dependency" or state.get("mode") != "agentic_rag" else bool(usages),
    }
    await tb.emit(agent, "complete", out["attack_path"] or "Code context collected (no model output)",
                  {"reachable": out["reachable"], "confirmed": len(out["confirmed"]), "hypotheses": len(out["hypotheses"])})
    return {"code_result": out, "completed": [agent], "tokens_in": ti, "tokens_out": to, "injection_signals": signals, "last_error": None}


def compute_risk(f: Dict[str, Any], intel: Optional[Dict[str, Any]], code: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Deterministic, explainable risk score (0-10) and priority."""
    sev_base = {"CRITICAL": 9.0, "HIGH": 7.0, "MEDIUM": 5.0, "LOW": 2.5, "INFO": 1.0, "UNKNOWN": 4.0}
    cvss = (intel or {}).get("cvss_score") or f.get("cvss_score")
    base = float(cvss) if cvss else sev_base.get(f.get("severity"), 4.0)
    factors = [{"factor": "base", "value": base, "detail": f"CVSS {cvss}" if cvss else f"scanner severity {f.get('severity')}"}]
    score = base
    kev = (intel or {}).get("is_known_exploited")
    if kev:
        score += 2.0
        factors.append({"factor": "known_exploited", "value": +2.0, "detail": "Listed in CISA KEV"})
    elif kev is None and f.get("finding_type") == "dependency":
        factors.append({"factor": "known_exploited", "value": 0, "detail": "KEV status unavailable (not treated as negative)"})
    if (intel or {}).get("exploit_references"):
        score += 1.0
        factors.append({"factor": "public_exploit_reference", "value": +1.0, "detail": f"{len(intel['exploit_references'])} exploit-tagged references"})
    reach = (code or {}).get("static_reachability")
    if reach is False:
        score -= 1.5
        factors.append({"factor": "reachability", "value": -1.5, "detail": "No direct imports of the package found (transitive or unused)"})
    elif reach is True:
        score += 0.5
        factors.append({"factor": "reachability", "value": +0.5, "detail": "Package is directly imported by application code"})
    if f.get("finding_type") == "secret":
        score = max(score, 8.0)
        factors.append({"factor": "credential_exposure", "value": "floor 8.0", "detail": "Exposed credentials are directly abusable"})
    if not f.get("fixed_version") and f.get("finding_type") == "dependency" and not (intel or {}).get("fixed_versions"):
        factors.append({"factor": "no_fix_available", "value": 0, "detail": "No fixed version published — mitigation required"})
    score = round(max(0.0, min(10.0, score)), 1)
    priority = "P1" if score >= 9 else "P2" if score >= 7 else "P3" if score >= 4 else "P4"
    return {"risk_score": score, "priority": priority, "factors": factors}


async def risk_assessment(state: InvestigationState, config) -> Dict[str, Any]:
    tb, f = _tb(config), state["finding"]
    agent = "risk_assessment"
    await tb.emit(agent, "start", "Assessing exploitability and business impact")
    risk = compute_risk(f, state.get("intel"), state.get("code_result"))
    await tb.emit(agent, "decision", f"Deterministic risk score {risk['risk_score']} → {risk['priority']}", {"factors": risk["factors"]})
    schema = '{"business_impact": str, "rationale": str, "why_now": str, "claims": [{"text": str, "citations": ["S1"]}]}'
    user = (_finding_brief(f, include_code=False) + f"\n\nComputed risk: {risk}\n\nCode analysis: "
            + untrusted("analysis", str({k: (state.get("code_result") or {}).get(k) for k in ("attack_path", "reachable", "exposure")}), 2000)
            + "\n\n" + format_evidence_for_prompt(state.get("evidence") or [], 5000)
            + "\nExplain the prioritization. Do not change the computed score.")
    data, ti, to = await _safe_llm(tb, agent, schema, user)
    eids = {e["citation_id"] for e in state.get("evidence") or []}
    risk.update({"business_impact": (data or {}).get("business_impact"), "rationale": (data or {}).get("rationale"),
                 "why_now": (data or {}).get("why_now"), "claims": valid_citations((data or {}).get("claims"), eids), "model_used": data is not None})
    await tb.emit(agent, "complete", risk.get("rationale") or f"Priority {risk['priority']} (score {risk['risk_score']})", {"priority": risk["priority"]})
    return {"risk": risk, "completed": [agent], "tokens_in": ti, "tokens_out": to, "last_error": None}


async def remediation(state: InvestigationState, config) -> Dict[str, Any]:
    tb, f = _tb(config), state["finding"]
    agent = "remediation"
    await tb.emit(agent, "start", "Preparing remediation proposal")
    intel = state.get("intel") or {}
    out: Dict[str, Any] = {"type": None, "patch": None, "files_changed": [], "steps": [], "side_effects": None, "evidence_sufficient": False}
    ti = to = 0

    if f.get("finding_type") == "dependency":
        target = _choose_fixed(f, intel)
        out["type"] = "dependency_upgrade"
        if target:
            manifests = await tb.manifest_reader(f)
            patch = tb.patcher(f, target, manifests)
            out.update({"target_version": target, "patch": patch.get("diff"), "files_changed": patch.get("files", []),
                        "patch_note": patch.get("note")})
            out["evidence_sufficient"] = bool(patch.get("diff"))
            out["steps"] = [f"Upgrade {f['package_name']} from {f.get('installed_version')} to {target}",
                            "Regenerate lock files and run the test suite", "Re-scan to confirm the advisory no longer matches"]
            await tb.emit(agent, "tool_call", f"Generated manifest patch to {target}" if patch.get("diff") else f"Could not patch manifest: {patch.get('note')}",
                          {"files": patch.get("files", [])})
        else:
            out["steps"] = ["No fixed version is published. Mitigate by removing/replacing the dependency or restricting the vulnerable functionality."]
    elif f.get("finding_type") == "secret":
        out["type"] = "secret_rotation"
        out["steps"] = ["Revoke/rotate the exposed credential at the issuing provider immediately",
                        "Remove the literal from source and load it from a secret manager or environment variable",
                        "Purge the secret from git history (e.g. git filter-repo) and audit provider logs for misuse"]
        out["evidence_sufficient"] = False  # rotation must be performed by a human at the provider

    schema = ('{"root_cause": str, "fix_summary": str, "steps": [str], "side_effects": str, "confidence": "high"|"medium"|"low", '
              '"patched_code": str|null, "claims": [{"text": str, "citations": ["S1"]}]}')
    want_code = f.get("finding_type") in ("sast", "misconfig") and tb.llm.may_receive_source and f.get("code_snippet")
    user = _finding_brief(f, include_code=bool(want_code)) + "\n\n" + format_evidence_for_prompt(state.get("evidence") or [], 5000)
    if want_code:
        user += ("\n\nIf a safe code fix is clear, set patched_code to the corrected replacement for exactly the lines shown in the code block "
                 "(without line-number prefixes, preserving indentation). Otherwise null.")
    data, ti, to = await _safe_llm(tb, agent, schema, user)
    if data:
        out["root_cause"] = data.get("root_cause")
        out["fix_summary"] = data.get("fix_summary")
        out["side_effects"] = data.get("side_effects") or out["side_effects"]
        out["confidence"] = data.get("confidence")
        if not out["steps"]:
            out["steps"] = [str(s) for s in (data.get("steps") or [])][:10]
        out["claims"] = valid_citations(data.get("claims"), {e["citation_id"] for e in state.get("evidence") or []})
        if want_code and data.get("patched_code"):
            manifests = await tb.manifest_reader(f)
            patch = tb.patcher(f, None, manifests, replacement=data["patched_code"])
            if patch.get("diff"):
                out.update({"type": "code_patch", "patch": patch["diff"], "files_changed": patch["files"]})
                out["evidence_sufficient"] = data.get("confidence") in ("high", "medium")
                await tb.emit(agent, "tool_call", "Model-proposed code patch converted to unified diff", {"files": patch["files"]})
            else:
                await tb.emit(agent, "decision", f"Model code patch rejected: {patch.get('note')}")
    out["type"] = out["type"] or "guidance"
    out["model_used"] = data is not None
    await tb.emit(agent, "complete", out.get("fix_summary") or (out["steps"][0] if out["steps"] else "Remediation guidance prepared"),
                  {"type": out["type"], "has_patch": bool(out["patch"]), "evidence_sufficient": out["evidence_sufficient"]})
    return {"remediation_result": out, "completed": [agent], "tokens_in": ti, "tokens_out": to, "last_error": None}


async def finalize(state: InvestigationState, config) -> Dict[str, Any]:
    tb, f = _tb(config), state["finding"]
    r, c, k, m = state.get("research") or {}, state.get("code_result") or {}, state.get("risk") or {}, state.get("remediation_result") or {}
    lines = []
    lines.append(r.get("model_summary") or f"{f.get('title')} ({f.get('vuln_id') or f.get('rule_id')})")
    if k:
        lines.append(f"Priority {k.get('priority')} with risk score {k.get('risk_score')}/10.")
    facts = r.get("facts") or {}
    if facts.get("known_exploited") is True:
        lines.append("Listed in CISA KEV (actively exploited).")
    if c.get("attack_path"):
        lines.append(f"Attack path: {c['attack_path']}")
    if m.get("fix_summary") or m.get("steps"):
        lines.append(f"Recommended fix: {m.get('fix_summary') or m['steps'][0]}")
    failed = state.get("failed") or []
    if failed:
        lines.append(f"Incomplete: {', '.join(failed)} did not complete.")
    summary = " ".join(lines)
    await tb.emit("supervisor", "complete", "Investigation complete" + (f" (failed: {', '.join(failed)})" if failed else ""),
                  {"tokens_in": state.get("tokens_in", 0), "tokens_out": state.get("tokens_out", 0)})
    return {"summary": summary, "next": "end"}


# --------------------------------------------------------------------------- helpers


# Distribution names whose import name differs (Python); npm names are imported as-is.
_IMPORT_ALIASES = {
    "pyyaml": ["yaml"], "beautifulsoup4": ["bs4"], "pillow": ["PIL"], "scikit-learn": ["sklearn"], "python-dateutil": ["dateutil"],
    "opencv-python": ["cv2"], "pyjwt": ["jwt"], "python-jose": ["jose"], "pycryptodome": ["Crypto"], "protobuf": ["google.protobuf"],
    "msgpack-python": ["msgpack"], "python-multipart": ["multipart"], "attrs": ["attr", "attrs"], "markupsafe": ["markupsafe"],
}


def import_names(package: str) -> List[str]:
    if package.startswith("@"):
        return [package]  # scoped npm packages are required by full name
    base = package.split("/")[-1]
    names = {base, base.replace("-", "_")}
    names.update(_IMPORT_ALIASES.get(base.lower(), []))
    if base.lower().startswith("python-"):
        names.add(base[7:].replace("-", "_"))
    return sorted(names)


async def _safe_llm(tb: Toolbox, agent: str, schema: str, user: str):
    for attempt in (1, 2):
        try:
            return await _llm_json(tb, agent, schema, user)
        except LLMUnavailable as e:
            if attempt == 1 and "Timeout" in str(e):
                await tb.emit(agent, "decision", "Model call timed out (cold start?) — retrying once")
                continue
            await tb.emit(agent, "error", f"Model unavailable — continuing with structured evidence only: {e}")
            return None, 0, 0
    return None, 0, 0


def _merge_evidence(existing: List[Dict], new: List[Dict]) -> List[Dict]:
    seen = {(e["title"], e["text"][:80]) for e in existing}
    merged = list(existing)
    for e in new:
        if (e["title"], e["text"][:80]) not in seen:
            merged.append(dict(e))
    for i, e in enumerate(merged, 1):
        e["citation_id"] = f"S{i}"
    return merged


def _intel_brief(intel: Optional[Dict[str, Any]]) -> str:
    if not intel:
        return "none (no vulnerability identifier)"
    kev = {True: "LISTED in CISA KEV", False: "not listed in CISA KEV", None: "KEV status unavailable"}[intel.get("is_known_exploited")]
    return (f"id={intel['vuln_id']} aliases={intel.get('aliases')}\nCVSS={intel.get('cvss_score')} {intel.get('cvss_severity')} {intel.get('cvss_vector')}\n"
            f"CWE={intel.get('cwe_ids')}\nfixed_versions={intel.get('fixed_versions')}\n{kev}\nexploit_refs={len(intel.get('exploit_references') or [])}\n"
            f"sources={ {k: v.get('status') for k, v in (intel.get('sources') or {}).items()} }")


def _intel_facts(intel: Optional[Dict[str, Any]], f: Dict[str, Any]) -> Dict[str, Any]:
    intel = intel or {}
    return {"vuln_id": intel.get("vuln_id") or f.get("vuln_id"), "cvss_score": intel.get("cvss_score") or f.get("cvss_score"),
            "cvss_vector": intel.get("cvss_vector"), "fixed_versions": intel.get("fixed_versions") or ([f["fixed_version"]] if f.get("fixed_version") else []),
            "known_exploited": intel.get("is_known_exploited"), "kev": intel.get("kev"),
            "exploit_references": (intel.get("exploit_references") or [])[:5], "published_at": intel.get("published_at"),
            "sources": {k: v.get("status") for k, v in (intel.get("sources") or {}).items()}}


def _vkey(v: str):
    return [int(x) if x.isdigit() else 0 for x in re.split(r"[.\-+]", v)]


def _choose_fixed(f: Dict[str, Any], intel: Dict[str, Any]) -> Optional[str]:
    """Smallest fixed version greater than installed, from scanner + intel data."""
    cands = set()
    for v in (f.get("fixed_version") or "").split(","):
        if v.strip():
            cands.add(v.strip())
    for a in intel.get("affected") or []:
        if (a.get("package") or "").lower() == (f.get("package_name") or "").lower():
            cands.update(a.get("fixed") or [])
    inst = f.get("installed_version") or "0"
    newer = [c for c in cands if re.match(r"^\d", c) and _vkey(c) > _vkey(inst)]
    if not newer:
        return None
    same_major = [c for c in newer if _vkey(c)[0] == _vkey(inst)[0]]
    return min(same_major or newer, key=_vkey)


def _guard(name: str, fn):
    """Convert specialist exceptions into a retryable error for the supervisor."""

    async def wrapped(state, config):
        try:
            return await fn(state, config)
        except Exception as e:  # noqa: BLE001
            await _tb(config).emit(name, "error", f"{type(e).__name__}: {e}"[:500])
            return {"last_error": f"{name}: {type(e).__name__}: {e}"[:500]}

    return wrapped


def build_graph():
    g = StateGraph(InvestigationState)
    g.add_node("supervisor", supervisor)
    g.add_node("vulnerability_research", _guard("vulnerability_research", vulnerability_research))
    g.add_node("code_analysis", _guard("code_analysis", code_analysis))
    g.add_node("risk_assessment", _guard("risk_assessment", risk_assessment))
    g.add_node("remediation", _guard("remediation", remediation))
    g.add_node("finalize", finalize)
    g.add_edge(START, "supervisor")
    g.add_conditional_edges("supervisor", route, {**{a: a for a in SPECIALISTS}, "finalize": "finalize", "supervisor": "supervisor"})
    for a in SPECIALISTS:
        g.add_edge(a, "supervisor")
    g.add_edge("finalize", END)
    return g.compile()


GRAPH = None


def get_graph():
    global GRAPH
    if GRAPH is None:
        GRAPH = build_graph()
    return GRAPH
