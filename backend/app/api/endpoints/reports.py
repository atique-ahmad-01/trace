"""Report endpoints (JSON or PDF via ?format=pdf)."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import OrgContext, get_org_context
from app.services import reports
from app.services.audit import audit

router = APIRouter()
FMT = Query("json", pattern="^(json|pdf)$")


async def _out(db, ctx, report, fmt, name):
    await audit(db, "report.export", org_id=ctx.org_id, user=ctx.user, details={"type": report["report_type"], "format": fmt})
    if fmt == "pdf":
        return Response(reports.render_pdf(report), media_type="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="trace-{name}.pdf"'})
    return report


async def _guard(coro):
    try:
        return await coro
    except LookupError as e:
        raise HTTPException(404, str(e))


@router.get("/executive")
async def executive(format: str = FMT, include_demo: bool = True, ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    return await _out(db, ctx, await reports.executive_report(db, ctx.org_id, include_demo), format, "executive-summary")


@router.get("/repository/{repo_id}")
async def repository(repo_id: uuid.UUID, format: str = FMT, ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    return await _out(db, ctx, await _guard(reports.repository_report(db, ctx.org_id, repo_id)), format, f"repository-{str(repo_id)[:8]}")


@router.get("/finding/{finding_id}")
async def finding(finding_id: uuid.UUID, format: str = FMT, ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    return await _out(db, ctx, await _guard(reports.finding_report(db, ctx.org_id, finding_id)), format, f"vulnerability-{str(finding_id)[:8]}")


@router.get("/ai-security/{assessment_id}")
async def ai_security(assessment_id: uuid.UUID, format: str = FMT, ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    return await _out(db, ctx, await _guard(reports.ai_security_report(db, ctx.org_id, assessment_id)), format, f"ai-security-{str(assessment_id)[:8]}")


@router.get("/remediation")
async def remediation(format: str = FMT, ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    return await _out(db, ctx, await reports.remediation_report(db, ctx.org_id), format, "remediation")


@router.get("/evaluation/{run_id}")
async def evaluation(run_id: uuid.UUID, format: str = FMT, ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    return await _out(db, ctx, await _guard(reports.evaluation_report(db, ctx.org_id, run_id)), format, f"evaluation-{str(run_id)[:8]}")
