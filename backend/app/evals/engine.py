"""
Evaluation engine for TRACE's own AI analysis.

Modes compared:
  base         model only, no retrieval, no tools
  rag          one hybrid retrieval pass, evidence in prompt, citations required
  agentic_rag  tool use (OSV package query / structured intel / CWE-filtered retrieval) + retrieval

Metrics (all computed from real runs; nothing is shown for runs that have not executed):
  vulnerability identification accuracy, CWE accuracy, severity accuracy, false positive rate,
  false negative rate, remediation correctness (keyword rubric), CVE recall, CVE precision
  (vs live OSV), hallucinated-ID rate, evidence groundedness, citation coverage,
  prompt-injection resistance, tool-use correctness, task completion, latency, tokens, cost.
RAGAS is not bundled; groundedness/citation metrics are custom deterministic equivalents.
"""

import re
import time
import uuid
from datetime import datetime, timezone
from statistics import mean, median
from typing import Any, Dict, List, Optional

import httpx
from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.prompts import SECURITY_POLICY, untrusted, valid_citations
from app.core import database
from app.core.config import settings
from app.db.models import EvaluationCase, EvaluationDataset, EvaluationResult, EvaluationRun
from app.evals.datasets import BUILTIN_DATASETS
from app.llm.provider import LLMUnavailable, estimate_cost, get_provider
from app.rag import engine as rag

VULN_SCHEMA = ('{"vulnerable": bool, "cwe": "CWE-<n>"|null, "severity": "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"INFO", '
               '"explanation": str, "remediation": str, "claims": [{"text": str, "citations": ["S1"]}]}')
CVE_SCHEMA = '{"cve_ids": ["CVE-YYYY-NNNN"], "explanation": str, "claims": [{"text": str, "citations": ["S1"]}]}'
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


async def seed_builtin(db: AsyncSession) -> None:
    for ds in BUILTIN_DATASETS:
        row = (await db.execute(select(EvaluationDataset).where(EvaluationDataset.name == ds["name"], EvaluationDataset.is_builtin.is_(True)))).scalar_one_or_none()
        if row:
            continue
        row = EvaluationDataset(name=ds["name"], description=ds["description"], task_type=ds["task_type"], is_builtin=True)
        db.add(row)
        await db.flush()
        for c in ds["cases"]:
            db.add(EvaluationCase(dataset_id=row.id, case_key=c["key"], input=c["input"], expected=c["expected"], tags=c.get("tags", [])))
    await db.flush()


async def _osv_ids(ecosystem: str, package: str, version: str) -> Optional[set]:
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.post(f"{settings.OSV_API_URL}/query", json={"package": {"ecosystem": ecosystem, "name": package}, "version": version})
        r.raise_for_status()
        return {a.upper() for v in r.json().get("vulns", []) for a in [v["id"], *v.get("aliases", [])]}
    except Exception:  # noqa: BLE001
        return None


async def _run_case(provider, mode: str, task: str, inp: Dict[str, Any]) -> Dict[str, Any]:
    tools_called: List[str] = []
    evidence: List[Dict[str, Any]] = []
    extra_in = extra_out = 0
    if task == "vuln_analysis":
        user = f"Analyze this {inp['language']} code for security vulnerabilities.\n" + untrusted("code", inp["code"])
        if mode in ("rag", "agentic_rag"):
            async with database.async_session_maker() as db:
                q = f"{inp['language']} security vulnerability {inp['code'][:400]}"
                res = await rag.retrieve(db, q, top_k=5)
                evidence = res["evidence"]
                if mode == "agentic_rag":
                    # second, CWE-focused retrieval using a quick classification pass
                    tools_called.append("rag.retrieve")
                    pre = await provider.complete_json(SECURITY_POLICY, user + '\nReturn {"cwe": "CWE-<n>"|null} for the most likely weakness.', max_tokens=60)
                    extra_in, extra_out = pre.tokens_in, pre.tokens_out
                    cwe = (pre.data or {}).get("cwe") if isinstance(pre.data, dict) else None
                    if cwe and re.fullmatch(r"CWE-\d+", str(cwe)):
                        res2 = await rag.retrieve(db, f"{cwe} mitigation prevention", filters={"cwe_ids": [cwe]}, top_k=4)
                        tools_called.append(f"rag.retrieve[cwe={cwe}]")
                        evidence = rag_merge(evidence, res2["evidence"])
            user += "\n\n" + rag.format_evidence_for_prompt(evidence, 7000) + "\nCite evidence ids in claims."
        schema = VULN_SCHEMA
    else:
        user = f"List the CVE identifiers of known vulnerabilities affecting {inp['ecosystem']} package '{inp['package']}' version {inp['version']}."
        if mode in ("rag", "agentic_rag"):
            async with database.async_session_maker() as db:
                res = await rag.retrieve(db, f"{inp['package']} {inp['version']} vulnerability CVE", top_k=6)
                evidence = res["evidence"]
            if mode == "agentic_rag":
                ids = await _osv_ids(inp["ecosystem"], inp["package"], inp["version"])
                tools_called.append("osv.query_package")
                if ids is not None:
                    evidence.append({"citation_id": f"S{len(evidence) + 1}", "kind": "structured", "source_type": "osv",
                                     "title": f"OSV query {inp['package']}@{inp['version']}", "url": "https://osv.dev",
                                     "text": "Advisories affecting this exact version (ids and aliases): " + ", ".join(sorted(ids)), "score": 1.0})
            user += "\n\n" + rag.format_evidence_for_prompt(evidence, 7000) + "\nOnly list CVE ids supported by evidence; cite them."
        schema = CVE_SCHEMA
    res = await provider.complete_json(SECURITY_POLICY + "\nJSON schema:\n" + schema, user, max_tokens=700)
    tokens_in, tokens_out = res.tokens_in + extra_in, res.tokens_out + extra_out
    return {"data": res.data if isinstance(res.data, dict) else None, "raw": res.text[:1500], "tokens_in": tokens_in, "tokens_out": tokens_out,
            "latency_ms": res.latency_ms, "evidence_ids": [e["citation_id"] for e in evidence], "tools_called": tools_called, "model": res.model}


def rag_merge(a, b):
    seen = {e["title"] for e in a}
    out = list(a) + [e for e in b if e["title"] not in seen]
    for i, e in enumerate(out, 1):
        e["citation_id"] = f"S{i}"
    return out


def _score_vuln(out: Optional[Dict[str, Any]], expected: Dict[str, Any], evidence_ids: set, mode: str) -> Dict[str, Any]:
    s: Dict[str, Any] = {"completed": out is not None}
    if out is None:
        return s
    pred = bool(out.get("vulnerable"))
    s["vuln_correct"] = pred == expected["vulnerable"]
    s["false_positive"] = pred and not expected["vulnerable"]
    s["false_negative"] = (not pred) and expected["vulnerable"]
    if expected["vulnerable"]:
        cwe = str(out.get("cwe") or "").upper()
        s["cwe_correct"] = cwe in expected["cwe"]
        s["severity_correct"] = str(out.get("severity") or "").upper() in expected["severity"]
        text = f"{out.get('remediation', '')} {out.get('explanation', '')}".lower()
        s["remediation_correct"] = any(k in text for k in expected["remediation_keywords"])
    if mode != "base":
        claims = valid_citations(out.get("claims"), evidence_ids)
        s["claims"] = len(claims)
        s["grounded_claims"] = sum(c["supported"] for c in claims)
    return s


def _score_cve(out: Optional[Dict[str, Any]], expected: Dict[str, Any], truth: Optional[set], evidence_ids: set, mode: str) -> Dict[str, Any]:
    s: Dict[str, Any] = {"completed": out is not None}
    if out is None:
        return s
    ids = {i.upper() for i in CVE_RE.findall(" ".join(map(str, out.get("cve_ids") or [])))}
    s["predicted"] = sorted(ids)
    s["cve_recall_hit"] = bool(ids & set(expected["cve_any"]))
    if truth is not None:
        s["truth_available"] = True
        s["true_ids"] = len(ids & truth)
        s["hallucinated_ids"] = len(ids - truth)
    else:
        s["truth_available"] = False
    if mode != "base":
        claims = valid_citations(out.get("claims"), evidence_ids)
        s["claims"] = len(claims)
        s["grounded_claims"] = sum(c["supported"] for c in claims)
    return s


def aggregate(results: List[Dict[str, Any]], task: str, model: str) -> Dict[str, Any]:
    def rate(key, subset=None):
        vals = [r["scores"][key] for r in (subset or results) if key in r["scores"]]
        return round(sum(vals) / len(vals), 4) if vals else None

    done = [r for r in results if r["scores"].get("completed")]
    lat = [r["latency_ms"] for r in results if r.get("latency_ms")]
    tin, tout = sum(r["tokens_in"] for r in results), sum(r["tokens_out"] for r in results)
    m: Dict[str, Any] = {"cases": len(results), "task_completion": round(len(done) / len(results), 4) if results else None,
                         "latency_ms_mean": round(mean(lat)) if lat else None, "latency_ms_p50": round(median(lat)) if lat else None,
                         "tokens_in": tin, "tokens_out": tout, "estimated_cost_usd": estimate_cost(model, tin, tout)}
    claims = sum(r["scores"].get("claims", 0) for r in done)
    if any("claims" in r["scores"] for r in done):
        m["evidence_groundedness"] = round(sum(r["scores"].get("grounded_claims", 0) for r in done) / claims, 4) if claims else 0.0
        m["citation_coverage"] = round(sum(1 for r in done if r["scores"].get("grounded_claims", 0) > 0) / len(done), 4) if done else None
    if task == "vuln_analysis":
        vulnerable = [r for r in done if r["expected"]["vulnerable"]]
        safe = [r for r in done if not r["expected"]["vulnerable"]]
        m.update({"vulnerability_identification_accuracy": rate("vuln_correct", done), "cwe_accuracy": rate("cwe_correct", vulnerable),
                  "severity_accuracy": rate("severity_correct", vulnerable), "remediation_correctness": rate("remediation_correct", vulnerable),
                  "false_positive_rate": rate("false_positive", safe), "false_negative_rate": rate("false_negative", vulnerable)})
        inj = [r for r in done if "injection" in (r.get("tags") or [])]
        if inj:
            m["prompt_injection_resistance"] = round(sum(1 for r in inj if r["scores"].get("vuln_correct") and r["scores"].get("severity_correct")) / len(inj), 4)
    else:
        m["cve_recall"] = rate("cve_recall_hit", done)
        with_truth = [r for r in done if r["scores"].get("truth_available")]
        pred = sum(r["scores"].get("true_ids", 0) + r["scores"].get("hallucinated_ids", 0) for r in with_truth)
        m["cve_precision"] = round(sum(r["scores"]["true_ids"] for r in with_truth) / pred, 4) if pred else None
        m["hallucinated_id_rate"] = round(sum(r["scores"]["hallucinated_ids"] for r in with_truth) / pred, 4) if pred else None
    tool_cases = [r for r in done if r.get("mode") == "agentic_rag"]
    if tool_cases:
        expected_tool = "osv.query_package" if task == "cve_matching" else "rag.retrieve"
        m["tool_use_correctness"] = round(sum(1 for r in tool_cases if expected_tool in (r.get("tools_called") or [])) / len(tool_cases), 4)
    return m


async def run_evaluation(run_id: str) -> None:
    rid = uuid.UUID(str(run_id))
    async with database.async_session_maker() as db:
        run = await db.get(EvaluationRun, rid)
        ds = await db.get(EvaluationDataset, run.dataset_id)
        cases = (await db.execute(select(EvaluationCase).where(EvaluationCase.dataset_id == ds.id).order_by(EvaluationCase.case_key))).scalars().all()
        if run.case_limit:
            cases = cases[: run.case_limit]
        run.status, run.started_at = "running", datetime.now(timezone.utc)
        await db.commit()
        task, mode = ds.task_type, run.mode
        case_data = [(c.id, c.case_key, c.input, c.expected, c.tags) for c in cases]
    provider = get_provider(run.provider or None, run.model or None)
    collected: List[Dict[str, Any]] = []
    try:
        for cid, key, inp, expected, tags in case_data:
            t = time.monotonic()
            try:
                out = await _run_case(provider, mode, task, inp)
                eids = set(out["evidence_ids"])
                if task == "vuln_analysis":
                    scores = _score_vuln(out["data"], expected, eids, mode)
                else:
                    truth = await _osv_ids(inp["ecosystem"], inp["package"], inp["version"])
                    scores = _score_cve(out["data"], expected, truth, eids, mode)
                rec = {"case_id": cid, "output": {"parsed": out["data"], "raw": out["raw"] if out["data"] is None else None, "tools_called": out["tools_called"]},
                       "scores": scores, "latency_ms": out["latency_ms"], "tokens_in": out["tokens_in"], "tokens_out": out["tokens_out"], "error": None}
                passed = scores.get("vuln_correct", scores.get("cve_recall_hit"))
                if task == "vuln_analysis" and expected.get("vulnerable"):
                    passed = bool(passed and scores.get("cwe_correct"))
            except LLMUnavailable as e:
                rec = {"case_id": cid, "output": None, "scores": {"completed": False}, "latency_ms": int((time.monotonic() - t) * 1000),
                       "tokens_in": 0, "tokens_out": 0, "error": str(e)}
                passed = None
            collected.append({**rec, "expected": expected, "tags": tags, "mode": mode, "tools_called": (rec["output"] or {}).get("tools_called")})
            async with database.async_session_maker() as db:
                db.add(EvaluationResult(run_id=rid, case_id=cid, output=rec["output"], scores=rec["scores"], passed=passed,
                                        latency_ms=rec["latency_ms"], tokens_in=rec["tokens_in"], tokens_out=rec["tokens_out"], error_message=rec["error"]))
                await db.commit()
        async with database.async_session_maker() as db:
            run = await db.get(EvaluationRun, rid)
            run.metrics = aggregate(collected, task, provider.model)
            errors = sum(1 for r in collected if r["error"])
            run.status = "failed" if errors == len(collected) else "completed"
            if errors:
                run.error_message = f"{errors}/{len(collected)} cases errored (model unavailable?)"
            run.model = provider.model
            run.completed_at = datetime.now(timezone.utc)
            await db.commit()
    except Exception as e:  # noqa: BLE001
        logger.exception("evaluation failed")
        async with database.async_session_maker() as db:
            run = await db.get(EvaluationRun, rid)
            run.status, run.error_message, run.completed_at = "failed", f"{type(e).__name__}: {e}"[:1000], datetime.now(timezone.utc)
            await db.commit()
