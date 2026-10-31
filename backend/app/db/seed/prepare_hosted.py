"""
Prepare a hosted database for a serverless deployment (SERVERLESS mode skips all of this at startup).

Runs the migrations, seeds the admin, demo organization and DEMO repository, scans the vulnerable
fixture with the real scanners installed on this machine, and ingests the OWASP/CWE knowledge base.
Every step is idempotent, so it is safe to re-run.

    DATABASE_URL=... DEMO_ADMIN_PASSWORD=... ENVIRONMENT=production \
        python -m app.db.seed.prepare_hosted
"""

import asyncio
import uuid
import sys

from loguru import logger
from sqlalchemy import func, select

from app.core import database
from app.core.config import settings
from app.db.models import RagDocument, Repository, Scan, User


async def main() -> int:
    if settings.SERVERLESS:
        logger.error("Run this from a machine with the scanners installed, not inside the serverless function")
        return 2
    if not settings.demo_admin_password_ok:
        logger.error("Set DEMO_ADMIN_PASSWORD (12+ characters, not the default) before seeding a production database")
        return 2

    from app.db.seed.seed import seed
    from app.main import run_migrations
    from app.rag.jobs import ingest_job
    from app.services.scan_service import run_scan

    logger.info("Running migrations")
    await asyncio.to_thread(run_migrations)
    logger.info("Seeding admin, demo organization and DEMO repository")
    await seed(queue_jobs=False)

    async with database.async_session_maker() as db:
        repo = (await db.execute(select(Repository).where(Repository.full_name == "local/vulnerable-app", Repository.is_demo.is_(True)))).scalar_one_or_none()
        if not repo:
            logger.error("Demo repository missing; is backend/tests/fixtures/vulnerable-app present?")
            return 1
        done = (await db.execute(select(func.count(Scan.id)).where(Scan.repository_id == repo.id, Scan.status.in_(["COMPLETED", "PARTIAL"])))).scalar()
        scan_id = None
        if not done:
            admin = (await db.execute(select(User).where(User.email == settings.DEMO_ADMIN_EMAIL))).scalar_one()
            scan = Scan(organization_id=repo.organization_id, repository_id=repo.id, branch=repo.default_branch, trigger="seed_demo",
                        triggered_by=admin.id, scanners_requested=[], is_demo=True, auto_investigate=False, log=[])
            db.add(scan)
            await db.commit()
            scan_id = str(scan.id)
        has_docs = (await db.execute(select(func.count(RagDocument.id)))).scalar()

    if scan_id:
        logger.info("Scanning the vulnerable fixture (a few minutes)")
        await run_scan(scan_id)
        async with database.async_session_maker() as db:
            scan = await db.get(Scan, uuid.UUID(scan_id))
            logger.info(f"Demo scan finished: {scan.status}")
            if scan.status not in ("COMPLETED", "PARTIAL"):
                logger.error(f"Demo scan did not complete: {scan.error_message}")
                return 1
    else:
        logger.info("Demo scan already completed; skipping")

    if not has_docs:
        logger.info("Ingesting the OWASP and CWE knowledge base")
        await ingest_job("owasp,cwe")
    else:
        logger.info("Knowledge base already ingested; skipping")

    await database.engine.dispose()
    logger.info("Hosted database is ready")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
