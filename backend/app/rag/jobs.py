"""Background RAG ingestion job."""

from loguru import logger

from app.core import database
from app.rag import engine as rag


async def ingest_job(sources: str) -> None:
    for src in [s for s in sources.split(",") if s]:
        async with database.async_session_maker() as db:
            try:
                if src == "owasp":
                    res = await rag.ingest_owasp(db)
                elif src == "cwe":
                    from sqlalchemy import select

                    from app.db.models import Finding

                    found = {c for row in (await db.execute(select(Finding.cwe_ids))).scalars() for c in (row or [])}
                    res = await rag.ingest_cwes(db, set(rag.DEFAULT_CWES) | {c.replace("CWE-", "") for c in found})
                elif src == "vuln_intel":
                    res = await rag.ingest_vuln_records(db)
                elif src == "reembed":
                    res = {"reembedded": await rag.reembed_missing(db)}
                else:
                    continue
                await db.commit()
                logger.info(f"RAG ingest {src}: {res}")
            except Exception:  # noqa: BLE001
                logger.exception(f"RAG ingest {src} failed")
                await db.rollback()
