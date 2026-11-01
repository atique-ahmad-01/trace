import os
import sys
import tempfile
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="trace-test-")
os.environ.update({
    "ENVIRONMENT": "test",
    # TEST_DATABASE_URL runs the suite on another database, e.g. PostgreSQL.
    "DATABASE_URL": os.environ.get("TEST_DATABASE_URL") or f"sqlite+aiosqlite:///{_TMP}/test.db",
    "QDRANT_PATH": f"{_TMP}/qdrant",
    "WORK_DIR": f"{_TMP}/work",
    "EMBEDDING_PROVIDER": "none",
    "MODEL_PROVIDER": "none",
    "SEED_DEMO_DATA": "false",
    "RATE_LIMIT_PER_MINUTE": "0",
    "GITHUB_WEBHOOK_SECRET": "test-webhook-secret",
    "SECRET_KEY": "test-secret",
    "JWT_SECRET_KEY": "test-jwt-secret",
})
if os.path.exists("/usr/bin/git"):
    os.environ.setdefault("GIT_PATH", "/usr/bin/git")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402

from app.core.database import Base, engine  # noqa: E402
from app.db import models  # noqa: E402,F401
from app.main import app  # noqa: E402

FIXTURE = Path(__file__).parent / "fixtures" / "vulnerable-app"


@pytest_asyncio.fixture(scope="session", autouse=True)
async def _schema():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


async def verify(client, register_response) -> None:
    """Opens the verification link a registration returned (tests run without SMTP)."""
    body = register_response.json()
    if body.get("verification_required"):
        token = body["verification_url"].split("token=", 1)[1]
        r = await client.post("/api/v1/auth/verify-email", json={"token": token})
        assert r.status_code == 200, r.text


async def register(client, name: str) -> dict:
    email = f"{name}@example.com"
    r = await client.post("/api/v1/auth/register", json={"email": email, "username": name, "password": "correct-horse-battery"})
    assert r.status_code == 201, r.text
    await verify(client, r)
    tok = (await client.post("/api/v1/auth/login", data={"username": email, "password": "correct-horse-battery"})).json()["access_token"]
    return {"Authorization": f"Bearer {tok}"}


@pytest.fixture
def scanners_available():
    from app.scanners.adapters import scanner_status

    missing = [s["name"] for s in scanner_status() if not s["available"]]
    if missing:
        pytest.skip(f"scanners not installed: {missing}")


def pytest_collection_modifyitems(items):
    # Run every async test on the session loop shared with the DB engine.
    for item in items:
        if item.get_closest_marker("asyncio"):
            item.add_marker(pytest.mark.asyncio(loop_scope="session"), append=False)
