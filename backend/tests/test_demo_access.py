"""Public demo: sign-ups get read-only access to the seeded TRACE Demo organization."""

import pytest
from sqlalchemy import delete, select

from app.core import database
from app.db.models import Organization, OrganizationMember, User

from .conftest import register, verify

pytestmark = pytest.mark.asyncio


async def test_signup_joins_demo_org_as_viewer(client):
    async with database.async_session_maker() as db:
        owner = User(email="demo-owner@example.com", username="demo-owner", hashed_password="x")
        demo = Organization(name="TRACE Demo", slug="trace-demo")
        db.add_all([owner, demo])
        await db.flush()
        db.add(OrganizationMember(organization_id=demo.id, user_id=owner.id, role="owner"))
        await db.commit()
        demo_id = str(demo.id)
    try:
        r = await client.post("/api/v1/auth/register", json={"email": "visitor@example.com", "username": "visitor", "password": "correct-horse-battery"})
        assert r.status_code == 201, r.text
        assert r.json()["demo_organization_id"] == demo_id
        await verify(client, r)
        tok = (await client.post("/api/v1/auth/login", data={"username": "visitor@example.com", "password": "correct-horse-battery"})).json()["access_token"]
        h = {"Authorization": f"Bearer {tok}"}

        orgs = (await client.get("/api/v1/auth/me", headers=h)).json()["organizations"]
        assert [o["role"] for o in orgs] == ["owner", "viewer"]  # own org stays the default

        hd = {**h, "X-Organization-Id": demo_id}
        cur = (await client.get("/api/v1/organizations/current", headers=hd)).json()
        assert cur["role"] == "viewer"
        assert [m["email"] for m in cur["members"]] == ["visitor@example.com"]  # no other members' emails
        # Viewers cannot write.
        assert (await client.post("/api/v1/repositories", headers=hd, json={"provider": "local", "full_name": "x/y"})).status_code == 403
        assert (await client.post("/api/v1/scans", headers=hd, json={"repository_id": demo_id})).status_code == 403
    finally:
        async with database.async_session_maker() as db:
            await db.execute(delete(OrganizationMember).where(OrganizationMember.organization_id == demo.id))
            await db.execute(delete(Organization).where(Organization.id == demo.id))
            await db.commit()


async def test_signup_without_demo_org(client):
    async with database.async_session_maker() as db:
        assert (await db.execute(select(Organization).where(Organization.slug == "trace-demo"))).scalar_one_or_none() is None
    r = await client.post("/api/v1/auth/register", json={"email": "solo@example.com", "username": "solo", "password": "correct-horse-battery"})
    assert r.status_code == 201
    assert r.json()["demo_organization_id"] is None
    h = await register(client, "solo2")
    assert len((await client.get("/api/v1/auth/me", headers=h)).json()["organizations"]) == 1
