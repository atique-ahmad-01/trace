"""
Report builders (JSON) and PDF rendering (ReportLab).

Every report states its generation time, data scope and whether demo data is included.
"""

import io
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    AgentInvestigation, AISecurityAssessment, AISecurityResult, EvaluationDataset, EvaluationRun, Finding, FindingStatus,
    RemediationProposal, Repository, Scan, ScannerExecution, VerificationRun, VulnerabilityRecord,
)
from app.services.scan_service import posture_score

SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]


def _iso(dt):
    return dt.isoformat() if dt else None


def _finding_row(f: Finding, repo_name: Optional[str] = None) -> Dict[str, Any]:
    return {"id": str(f.id), "title": f.title, "severity": f.severity, "status": f.status, "type": f.finding_type, "scanner": f.scanner_name,
            "detected_by": f.detected_by, "vuln_id": f.vuln_id, "cwe_ids": f.cwe_ids, "cvss_score": f.cvss_score, "package": f.package_name,
            "installed_version": f.installed_version, "fixed_version": f.fixed_version, "file": f.file_path, "line": f.start_line,
            "priority": f.priority, "risk_score": f.risk_score, "repository": repo_name, "first_seen_at": _iso(f.first_seen_at),
            "is_demo": f.is_demo}


def _meta(kind: str, scope: Dict[str, Any], demo: bool) -> Dict[str, Any]:
    return {"report_type": kind, "generated_at": datetime.now(timezone.utc).isoformat(), "generator": "TRACE", "scope": scope,
            "includes_demo_data": demo}


async def repository_report(db: AsyncSession, org_id, repo_id: uuid.UUID) -> Dict[str, Any]:
    repo = await db.get(Repository, repo_id)
    if not repo or repo.organization_id != org_id:
        raise LookupError("repository not found")
    findings = (await db.execute(select(Finding).where(Finding.repository_id == repo_id).order_by(Finding.severity))).scalars().all()
    scans = (await db.execute(select(Scan).where(Scan.repository_id == repo_id).order_by(Scan.created_at.desc()).limit(20))).scalars().all()
    open_f = [f for f in findings if f.status == FindingStatus.OPEN.value]
    latest = scans[0] if scans else None
    execs = (await db.execute(select(ScannerExecution).where(ScannerExecution.scan_id == latest.id))).scalars().all() if latest else []
    return {
        **_meta("repository", {"repository": repo.full_name}, repo.is_demo),
        "repository": {"name": repo.full_name, "provider": repo.provider, "default_branch": repo.default_branch, "ecosystems": repo.ecosystems,
                       "security_score": repo.security_score, "last_scanned_at": _iso(repo.last_scanned_at), "last_scanned_commit": repo.last_scanned_commit},
        "summary": {"open": len(open_f), "resolved": sum(f.status == "RESOLVED" for f in findings),
                    "by_severity": {s: sum(f.severity == s for f in open_f) for s in SEVS},
                    "by_type": {t: sum(f.finding_type == t for f in open_f) for t in sorted({f.finding_type for f in open_f})}},
        "latest_scan": {"id": str(latest.id), "commit": latest.commit_sha, "status": latest.status, "completed_at": _iso(latest.completed_at),
                        "scanners": [{"name": e.scanner_name, "status": e.status, "version": e.scanner_version, "findings": e.findings_count,
                                      "error": e.error_message} for e in execs]} if latest else None,
        "scan_history": [{"id": str(s.id), "commit": s.commit_sha, "status": s.status, "total": s.total_findings, "created_at": _iso(s.created_at)} for s in scans],
        "findings": [_finding_row(f, repo.full_name) for f in sorted(open_f, key=lambda f: (SEVS.index(f.severity), -(f.cvss_score or 0)))],
    }


async def finding_report(db: AsyncSession, org_id, finding_id: uuid.UUID) -> Dict[str, Any]:
    f = await db.get(Finding, finding_id)
    if not f or f.organization_id != org_id:
        raise LookupError("finding not found")
    repo = await db.get(Repository, f.repository_id)
    rec = (await db.execute(select(VulnerabilityRecord).where(VulnerabilityRecord.vuln_id == f.vuln_id))).scalar_one_or_none() if f.vuln_id else None
    inv = (await db.execute(select(AgentInvestigation).where(AgentInvestigation.finding_id == f.id).order_by(AgentInvestigation.created_at.desc()).limit(1))).scalar_one_or_none()
    props = (await db.execute(select(RemediationProposal).where(RemediationProposal.finding_id == f.id))).scalars().all()
    from app.intel.service import record_to_dict

    return {
        **_meta("vulnerability", {"finding": str(f.id), "repository": repo.full_name}, f.is_demo),
        "finding": {**_finding_row(f, repo.full_name), "description": f.description, "references": f.references, "code_snippet": f.code_snippet},
        "intelligence": record_to_dict(rec) if rec else None,
        "investigation": {"status": inv.status, "summary": inv.summary, "risk": inv.risk_assessment, "citations": inv.citations,
                          "model": inv.model, "completed_at": _iso(inv.completed_at)} if inv else None,
        "remediation": [{"title": p.title, "type": p.remediation_type, "status": p.status, "pr_url": p.pr_url} for p in props],
    }


async def executive_report(db: AsyncSession, org_id, include_demo: bool = True) -> Dict[str, Any]:
    q = select(Finding).where(Finding.organization_id == org_id)
    if not include_demo:
        q = q.where(Finding.is_demo.is_(False))
    findings = (await db.execute(q)).scalars().all()
    repos = {r.id: r for r in (await db.execute(select(Repository).where(Repository.organization_id == org_id))).scalars()}
    open_f = [f for f in findings if f.status == "OPEN"]
    counts = {s: sum(f.severity == s for f in open_f) for s in SEVS}
    per_repo = {}
    for f in open_f:
        per_repo.setdefault(f.repository_id, []).append(f)
    top = sorted(per_repo.items(), key=lambda kv: -sum(10 if f.severity == "CRITICAL" else 5 if f.severity == "HIGH" else 1 for f in kv[1]))[:10]
    props = (await db.execute(select(RemediationProposal.status, func.count()).where(RemediationProposal.organization_id == org_id).group_by(RemediationProposal.status))).all()
    kev_ids = {r.vuln_id for r in (await db.execute(select(VulnerabilityRecord).where(VulnerabilityRecord.is_known_exploited.is_(True)))).scalars()}
    kev_open = [f for f in open_f if f.vuln_id in kev_ids]
    return {
        **_meta("executive_summary", {"organization": str(org_id)}, any(f.is_demo for f in findings)),
        "posture_score": posture_score(counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"]),
        "open_findings": len(open_f), "resolved_findings": sum(f.status == "RESOLVED" for f in findings), "by_severity": counts,
        "known_exploited_open": [_finding_row(f, repos[f.repository_id].full_name) for f in kev_open][:20],
        "top_risk_repositories": [{"repository": repos[rid].full_name, "open": len(fs), "critical": sum(f.severity == "CRITICAL" for f in fs),
                                   "high": sum(f.severity == "HIGH" for f in fs), "score": repos[rid].security_score} for rid, fs in top],
        "remediation_status": {s: c for s, c in props},
        "top_priorities": [_finding_row(f, repos[f.repository_id].full_name) for f in sorted(open_f, key=lambda f: (-(f.risk_score or 0), SEVS.index(f.severity)))[:15]],
    }


async def ai_security_report(db: AsyncSession, org_id, assessment_id: uuid.UUID) -> Dict[str, Any]:
    a = await db.get(AISecurityAssessment, assessment_id)
    if not a or a.organization_id != org_id:
        raise LookupError("assessment not found")
    results = (await db.execute(select(AISecurityResult).where(AISecurityResult.assessment_id == a.id))).scalars().all()
    return {
        **_meta("ai_security_assessment", {"assessment": a.name, "target_type": a.target_type}, False),
        "assessment": {"name": a.name, "status": a.status, "risk_score": a.risk_score, "total": a.total_tests, "failed": a.tests_failed,
                       "passed": a.tests_passed, "errored": a.tests_errored, "summary": a.summary, "target": a.target_config},
        "disclaimer": "Passing tests do not establish that the AI system is secure; they only show the listed probes did not demonstrate risk.",
        "results": [{"test_id": r.test_id, "category": r.category, "title": r.title, "outcome": r.outcome, "severity": r.severity,
                     "description": r.description, "evidence": r.evidence, "reproduction": r.reproduction, "impact": r.impact,
                     "mitigation": r.mitigation, "verification_status": r.verification_status, "location": f"{r.file_path}:{r.line_number}" if r.file_path else None}
                    for r in sorted(results, key=lambda r: (r.outcome != "failed", SEVS.index(r.severity) if r.severity in SEVS else 9))],
    }


async def remediation_report(db: AsyncSession, org_id) -> Dict[str, Any]:
    rows = (await db.execute(select(RemediationProposal, Finding).join(Finding, RemediationProposal.finding_id == Finding.id)
                             .where(RemediationProposal.organization_id == org_id).order_by(RemediationProposal.created_at.desc()))).all()
    out = []
    for p, f in rows:
        vr = (await db.execute(select(VerificationRun).where(VerificationRun.proposal_id == p.id).order_by(VerificationRun.created_at.desc()).limit(1))).scalar_one_or_none()
        out.append({"proposal": p.title, "finding": f.title, "severity": f.severity, "type": p.remediation_type, "status": p.status,
                    "evidence_sufficient": p.evidence_sufficient, "pr_url": p.pr_url, "verification": vr.status if vr else "not_run",
                    "created_at": _iso(p.created_at)})
    return {**_meta("remediation", {"organization": str(org_id)}, False), "proposals": out,
            "by_status": {s: sum(1 for o in out if o["status"] == s) for s in sorted({o["status"] for o in out})}}


async def evaluation_report(db: AsyncSession, org_id, run_id: uuid.UUID) -> Dict[str, Any]:
    run = await db.get(EvaluationRun, run_id)
    if not run or run.organization_id != org_id:
        raise LookupError("evaluation run not found")
    ds = await db.get(EvaluationDataset, run.dataset_id)
    return {**_meta("evaluation", {"run": run.name, "dataset": ds.name}, False),
            "run": {"mode": run.mode, "provider": run.provider, "model": run.model, "status": run.status, "started_at": _iso(run.started_at),
                    "completed_at": _iso(run.completed_at), "error": run.error_message},
            "metrics": run.metrics if run.status in ("completed",) else None,
            "note": None if run.status == "completed" else "Run has not completed — no metrics reported."}


# --------------------------------------------------------------------------- PDF


def render_pdf(report: Dict[str, Any]) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    from xml.sax.saxutils import escape

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
                            title=f"TRACE {report['report_type']} report")
    st = getSampleStyleSheet()
    small = st["BodyText"].clone("small", fontSize=8, leading=10)
    els = [Paragraph(f"TRACE — {report['report_type'].replace('_', ' ').title()} Report", st["Title"]),
           Paragraph(escape(f"Generated {report['generated_at']} · scope: {report['scope']}"), small)]
    if report.get("includes_demo_data"):
        els.append(Paragraph("<b>Includes sample/demo data.</b>", small))
    els.append(Spacer(1, 6 * mm))

    def p(text, style=small):
        return Paragraph(escape(str(text if text is not None else "—"))[:1500], style)

    def table(rows: List[List[Any]], widths=None):
        t = Table([[p(c) for c in r] for r in rows], colWidths=widths, repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                               ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#9ca3af")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        return t

    for key, val in report.items():
        if key in ("report_type", "generated_at", "generator", "scope", "includes_demo_data"):
            continue
        els.append(Paragraph(key.replace("_", " ").title(), st["Heading2"]))
        if isinstance(val, list) and val and isinstance(val[0], dict):
            cols = [c for c in val[0].keys() if c not in ("id", "evidence", "code_snippet", "references", "description", "detected_by")][:7]
            els.append(table([cols] + [[r.get(c) for c in cols] for r in val[:300]]))
        elif isinstance(val, dict):
            els.append(table([["Field", "Value"]] + [[k, v] for k, v in val.items()], widths=[50 * mm, 128 * mm]))
        else:
            els.append(p(val, st["BodyText"]))
        els.append(Spacer(1, 4 * mm))
    doc.build(els)
    return buf.getvalue()
