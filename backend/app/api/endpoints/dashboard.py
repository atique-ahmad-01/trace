"""Dashboard metrics — all values computed from the database."""

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.common import ser
from app.core.database import get_db
from app.core.deps import OrgContext, get_org_context
from app.db.models import AgentInvestigation, Finding, RemediationProposal, Repository, Scan
from app.services.scan_service import posture_score

router = APIRouter()
SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def _demo_filter(stmt, model, demo: Optional[bool]):
    return stmt.where(model.is_demo.is_(demo)) if demo is not None else stmt


@router.get("/summary")
async def summary(demo: Optional[bool] = Query(None, description="true=only demo, false=only real, omit=all"),
                  ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    org = ctx.org_id
    repos = (await db.execute(_demo_filter(select(func.count(Repository.id)).where(Repository.organization_id == org), Repository, demo))).scalar()
    scans = (await db.execute(_demo_filter(select(func.count(Scan.id)).where(Scan.organization_id == org), Scan, demo))).scalar()
    status_counts = dict((await db.execute(_demo_filter(select(Finding.status, func.count()).where(Finding.organization_id == org), Finding, demo)
                                           .group_by(Finding.status))).all())
    sev_open = dict((await db.execute(_demo_filter(select(Finding.severity, func.count()).where(Finding.organization_id == org, Finding.status == "OPEN"),
                                                   Finding, demo).group_by(Finding.severity))).all())
    type_open = dict((await db.execute(_demo_filter(select(Finding.finding_type, func.count()).where(Finding.organization_id == org, Finding.status == "OPEN"),
                                                    Finding, demo).group_by(Finding.finding_type))).all())
    scanner_open = dict((await db.execute(_demo_filter(select(Finding.scanner_name, func.count()).where(Finding.organization_id == org, Finding.status == "OPEN"),
                                                       Finding, demo).group_by(Finding.scanner_name))).all())
    demo_present = (await db.execute(select(func.count(Finding.id)).where(Finding.organization_id == org, Finding.is_demo.is_(True)))).scalar() > 0
    real_present = (await db.execute(select(func.count(Finding.id)).where(Finding.organization_id == org, Finding.is_demo.is_(False)))).scalar() > 0

    worst = (await db.execute(_demo_filter(select(Repository).where(Repository.organization_id == org, Repository.last_scanned_at.isnot(None)), Repository, demo)
                              .order_by(Repository.security_score.asc().nullslast()).limit(6))).scalars().all()
    worst_out = []
    for r in worst:
        c = dict((await db.execute(select(Finding.severity, func.count()).where(Finding.repository_id == r.id, Finding.status == "OPEN").group_by(Finding.severity))).all())
        worst_out.append({**ser(r, include=("id", "full_name", "security_score", "last_scanned_at", "is_demo")), "open": sum(c.values()), "severity_counts": c})

    recent_scans = (await db.execute(_demo_filter(select(Scan, Repository.full_name).join(Repository).where(Scan.organization_id == org), Scan, demo)
                                     .order_by(Scan.created_at.desc()).limit(8))).all()
    recent_findings = (await db.execute(_demo_filter(select(Finding, Repository.full_name).join(Repository).where(Finding.organization_id == org, Finding.status == "OPEN"),
                                                     Finding, demo).order_by(Finding.first_seen_at.desc()).limit(8))).all()
    inv_status = dict((await db.execute(select(AgentInvestigation.status, func.count()).where(AgentInvestigation.organization_id == org)
                                        .group_by(AgentInvestigation.status))).all())
    recent_inv = (await db.execute(select(AgentInvestigation, Finding.title).join(Finding, AgentInvestigation.finding_id == Finding.id)
                                   .where(AgentInvestigation.organization_id == org).order_by(AgentInvestigation.created_at.desc()).limit(5))).all()
    rem_status = dict((await db.execute(select(RemediationProposal.status, func.count()).where(RemediationProposal.organization_id == org)
                                        .group_by(RemediationProposal.status))).all())

    counts = {s: sev_open.get(s, 0) for s in SEVS}
    return {
        "data_scope": {"filter": "demo" if demo else "real" if demo is False else "all", "demo_data_present": demo_present, "real_data_present": real_present},
        "total_repositories": repos, "total_scans": scans,
        "open_findings": status_counts.get("OPEN", 0) + status_counts.get("IN_PROGRESS", 0), "resolved_findings": status_counts.get("RESOLVED", 0),
        "status_counts": status_counts, "severity_counts": {**counts, "INFO": sev_open.get("INFO", 0), "UNKNOWN": sev_open.get("UNKNOWN", 0)},
        "type_counts": type_open, "scanner_counts": scanner_open,
        "security_posture_score": posture_score(counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"]) if (repos and scans) else None,
        "most_vulnerable_repositories": worst_out,
        "recent_scans": [{**ser(s, include=("id", "status", "commit_sha", "branch", "total_findings", "critical_count", "high_count", "created_at",
                                            "completed_at", "trigger", "is_demo")), "repository_name": n} for s, n in recent_scans],
        "recent_findings": [{**ser(f, include=("id", "title", "severity", "vuln_id", "package_name", "file_path", "first_seen_at", "scanner_name", "is_demo")),
                             "repository_name": n} for f, n in recent_findings],
        "investigations": {"by_status": inv_status, "recent": [{**ser(i, include=("id", "status", "created_at", "model")), "finding_title": t,
                                                                 "priority": (i.risk_assessment or {}).get("priority")} for i, t in recent_inv]},
        "remediation": {"by_status": rem_status},
    }


@router.get("/trends")
async def trends(days: int = Query(30, ge=7, le=365), hours: Optional[int] = Query(None, ge=1, le=72), demo: Optional[bool] = None,
                 ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    """Open-finding counts by severity, reconstructed from first_seen_at / resolved_at.

    `hours` selects an intraday window (15-minute points up to 6h, hourly beyond); otherwise `days` gives daily points."""
    now = datetime.now(timezone.utc)
    if hours:
        step = timedelta(minutes=15) if hours <= 6 else timedelta(hours=1)
        start = now - timedelta(hours=hours)
        points = [start + step * i for i in range(int(timedelta(hours=hours) / step) + 1)]
        label = lambda t: t.isoformat(timespec="minutes")  # noqa: E731
    else:
        start = now - timedelta(days=days)
        points = [(start + timedelta(days=i)).replace(hour=23, minute=59, second=59) for i in range(days + 1)]
        label = lambda t: t.date().isoformat()  # noqa: E731
    utc = lambda t: t if (t is None or t.tzinfo) else t.replace(tzinfo=timezone.utc)  # noqa: E731
    rows = [(sev, utc(first), utc(resolved), status) for sev, first, resolved, status in (await db.execute(
        _demo_filter(select(Finding.severity, Finding.first_seen_at, Finding.resolved_at, Finding.status)
                     .where(Finding.organization_id == ctx.org_id), Finding, demo))).all()]
    series = []
    for at in points:
        point = defaultdict(int)
        for sev, first, resolved, status in rows:
            if first and first <= at and (resolved is None or resolved > at) and status not in ("FALSE_POSITIVE",):
                point[sev] += 1
        series.append({"date": label(at), **{s: point.get(s, 0) for s in SEVS}})
    new_by_day = defaultdict(int)
    for _, first, _, _ in rows:
        if first and first >= start:
            new_by_day[first.date().isoformat()] += 1
    return {"series": series, "new_by_day": [{"date": d, "count": c} for d, c in sorted(new_by_day.items())]}
