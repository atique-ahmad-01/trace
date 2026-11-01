"""
Database seed.

Creates the demo admin, organization, built-in MCP integration and evaluation
datasets, and connects the intentionally vulnerable fixture repository as a
clearly labeled DEMO repository. Demo findings are produced by actually scanning
the fixture — nothing is fabricated.

Run standalone: python -m app.db.seed.seed
"""

import asyncio
import os

from loguru import logger
from sqlalchemy import func, select

from app.core import database
from app.core.config import BACKEND_DIR, settings
from app.core.security import get_password_hash
from app.db.models import Organization, OrganizationMember, RagDocument, Repository, Scan, User

DEMO_FIXTURE = str(BACKEND_DIR / "tests" / "fixtures" / "vulnerable-app")


async def seed(queue_jobs: bool = True) -> None:
    from app.evals.engine import seed_builtin
    from app.mcp.service import ensure_builtin

    async with database.async_session_maker() as db:
        admin = (await db.execute(select(User).where(User.email == settings.DEMO_ADMIN_EMAIL))).scalar_one_or_none()
        if not admin:
            admin = User(email=settings.DEMO_ADMIN_EMAIL, username="admin", full_name="TRACE Admin",
                         hashed_password=get_password_hash(settings.DEMO_ADMIN_PASSWORD), is_superuser=True, email_verified=True)
            db.add(admin)
            await db.flush()
            logger.info(f"Created admin user {settings.DEMO_ADMIN_EMAIL}")
        org = (await db.execute(select(Organization).where(Organization.slug == "trace-demo"))).scalar_one_or_none()
        if not org:
            org = Organization(name="TRACE Demo", slug="trace-demo", description="Default organization")
            db.add(org)
            await db.flush()
            db.add(OrganizationMember(organization_id=org.id, user_id=admin.id, role="owner"))
        await ensure_builtin(db, org.id)
        await seed_builtin(db)

        repo = (await db.execute(select(Repository).where(Repository.organization_id == org.id, Repository.full_name == "local/vulnerable-app"))).scalar_one_or_none()
        new_repo = False
        if not repo and os.path.isdir(DEMO_FIXTURE):
            repo = Repository(organization_id=org.id, provider="local", name="vulnerable-app", full_name="local/vulnerable-app",
                              description="DEMO: intentionally vulnerable fixture (Python/Flask, npm, Dockerfile, insecure LLM agent)",
                              default_branch="local", language="Python", is_demo=True, extra={"local_path": DEMO_FIXTURE})
            db.add(repo)
            new_repo = True
        await db.commit()

        if queue_jobs and settings.ENVIRONMENT != "test":
            from app.services import jobs

            if repo and (new_repo or not (await db.execute(select(func.count(Scan.id)).where(Scan.repository_id == repo.id))).scalar()):
                from app.api.endpoints.scans import queue_scan

                await queue_scan(db, repo, trigger="seed_demo", user_id=admin.id)
                await db.commit()
                logger.info("Queued demo scan of the vulnerable fixture")
            if not (await db.execute(select(func.count(RagDocument.id)))).scalar():
                jobs.enqueue("app.rag.jobs.ingest_job", "owasp,cwe")
                logger.info("Queued initial RAG knowledge ingestion (OWASP, CWE)")


if __name__ == "__main__":
    asyncio.run(seed(queue_jobs=False))
    print("Seed complete")
