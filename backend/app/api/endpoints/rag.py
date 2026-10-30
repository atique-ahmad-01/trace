"""Security RAG knowledge endpoints."""

from typing import List, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.common import Page, paginate, ser
from app.core.database import get_db
from app.core.deps import OrgContext, get_org_context, require_role
from app.db.models import RagDocument, RagSource
from app.rag import engine as rag
from app.services import jobs
from app.services.audit import audit

router = APIRouter()


@router.get("/stats")
async def stats(ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    return await rag.stats(db)


@router.get("/sources")
async def sources(ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(RagSource).where(or_(RagSource.organization_id.is_(None), RagSource.organization_id == ctx.org_id))
                             .order_by(RagSource.name))).scalars().all()
    return [ser(s) for s in rows]


@router.get("/documents")
async def documents(source_id: Optional[str] = None, q: Optional[str] = None, page: Page = Depends(), ctx: OrgContext = Depends(get_org_context),
                    db: AsyncSession = Depends(get_db)):
    stmt = (select(RagDocument, RagSource.name).join(RagSource)
            .where(or_(RagSource.organization_id.is_(None), RagSource.organization_id == ctx.org_id)))
    if source_id:
        stmt = stmt.where(RagDocument.source_id == source_id)
    if q:
        stmt = stmt.where(RagDocument.title.ilike(f"%{q}%"))
    return await paginate(db, stmt.order_by(RagDocument.title), page,
                          mapper=lambda d, s: {**ser(d, exclude=("content",)), "source_name": s, "preview": d.content[:300]})


class SearchIn(BaseModel):
    query: str = Field(min_length=2, max_length=1000)
    source_type: Optional[List[str]] = None
    cwe_ids: Optional[List[str]] = None
    vuln_ids: Optional[List[str]] = None
    top_k: int = Field(default=6, ge=1, le=20)
    use_dense: bool = True
    use_keyword: bool = True


@router.post("/search")
async def search(body: SearchIn, ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    import re

    exact = re.findall(r"(?:CVE-\d{4}-\d{4,}|GHSA-[\w-]{14})", body.query, re.I)
    return await rag.retrieve(db, body.query, org_id=ctx.org_id, top_k=body.top_k, exact_ids=[e.upper() for e in exact],
                              filters={"source_type": body.source_type, "cwe_ids": body.cwe_ids, "vuln_ids": body.vuln_ids},
                              use_dense=body.use_dense, use_keyword=body.use_keyword)


class IngestIn(BaseModel):
    sources: List[str] = Field(default=["owasp", "cwe", "vuln_intel"])


@router.post("/ingest", status_code=202)
async def ingest(body: IngestIn, ctx: OrgContext = Depends(require_role("admin")), db: AsyncSession = Depends(get_db)):
    valid = [s for s in body.sources if s in ("owasp", "cwe", "vuln_intel", "reembed")]
    jobs.enqueue("app.rag.jobs.ingest_job", ",".join(valid))
    await audit(db, "rag.ingest", org_id=ctx.org_id, user=ctx.user, details={"sources": valid})
    return {"queued": valid}


class InternalDocIn(BaseModel):
    title: str = Field(min_length=3, max_length=300)
    content: str = Field(min_length=20, max_length=200_000)
    url: Optional[str] = Field(default=None, max_length=1000)


@router.post("/documents", status_code=201)
async def add_internal(body: InternalDocIn, ctx: OrgContext = Depends(require_role("admin")), db: AsyncSession = Depends(get_db)):
    doc = await rag.ingest_internal(db, ctx.org_id, body.title, body.content, body.url)
    await audit(db, "rag.internal_document", org_id=ctx.org_id, user=ctx.user, resource_type="rag_document", resource_id=doc.id, details={"title": body.title})
    return {**ser(doc, exclude=("content",)), "note": "Approved internal source; retrievable only within this organization."}
