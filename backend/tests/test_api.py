"""API tests: auth, org isolation, validation, webhooks, approval gates, MCP allowlist."""

import hashlib
import hmac
import json
import uuid

import pytest
from sqlalchemy import select

from app.core import database
from app.db.models import Finding, MCPTool, RemediationProposal, Repository

from .conftest import register

pytestmark = pytest.mark.asyncio


async def test_health_and_auth_required(client):
    assert (await client.get("/health")).json()["status"] == "healthy"
    assert (await client.get("/ready")).status_code == 200
    assert (await client.get("/api/v1/repositories")).status_code == 401
    assert (await client.get("/api/v1/repositories", headers={"Authorization": "Bearer junk"})).status_code == 401


async def test_register_validation_and_login_failure(client):
    r = await client.post("/api/v1/auth/register", json={"email": "bad", "username": "x", "password": "short"})
    assert r.status_code == 422
    r = await client.post("/api/v1/auth/login", data={"username": "nobody@example.com", "password": "whatever-123"})
    assert r.status_code == 401


async def test_org_isolation(client):
    a = await register(client, "alice")
    b = await register(client, "bob")
    r = await client.post("/api/v1/repositories", headers=a, json={"provider": "local", "local_path": "vulnerable-app"})
    assert r.status_code == 201, r.text
    repo_id = r.json()["id"]
    assert r.json()["is_demo"] is True
    assert (await client.get(f"/api/v1/repositories/{repo_id}", headers=a)).status_code == 200
    assert (await client.get(f"/api/v1/repositories/{repo_id}", headers=b)).status_code == 404
    assert (await client.get("/api/v1/repositories", headers=b)).json()["total"] == 0
    assert (await client.post("/api/v1/scans", headers=b, json={"repository_id": repo_id})).status_code == 404
    # forged org header for an org bob is not a member of
    me_a = (await client.get("/api/v1/auth/me", headers=a)).json()
    forged = {**b, "X-Organization-Id": me_a["organizations"][0]["id"]}
    assert (await client.get("/api/v1/repositories", headers=forged)).status_code == 403


async def test_local_path_traversal_rejected(client):
    h = await register(client, "carol")
    for p in ("../../", "/etc", "vulnerable-app/../../.."):
        r = await client.post("/api/v1/repositories", headers=h, json={"provider": "local", "local_path": p})
        assert r.status_code == 422, p
    r = await client.post("/api/v1/repositories", headers=h, json={"provider": "git", "clone_url": "file:///etc"})
    assert r.status_code == 422


async def test_webhook_signature_enforced(client):
    body = json.dumps({"zen": "hi", "installation": {"id": 1}}).encode()
    r = await client.post("/api/v1/webhooks/github", content=body, headers={"X-GitHub-Event": "ping", "X-Hub-Signature-256": "sha256=bad"})
    assert r.status_code == 401
    sig = "sha256=" + hmac.new(b"test-webhook-secret", body, hashlib.sha256).hexdigest()
    r = await client.post("/api/v1/webhooks/github", content=body, headers={"X-GitHub-Event": "ping", "X-Hub-Signature-256": sig})
    assert r.status_code == 200 and r.json()["zen"] == "hi"
    push = json.dumps({"ref": "refs/heads/main", "installation": {"id": 999}, "repository": {"full_name": "x/y"}}).encode()
    sig = "sha256=" + hmac.new(b"test-webhook-secret", push, hashlib.sha256).hexdigest()
    r = await client.post("/api/v1/webhooks/github", content=push, headers={"X-GitHub-Event": "push", "X-Hub-Signature-256": sig})
    assert r.json()["ignored"] == "unknown or suspended installation"


async def _seed_finding(headers, client) -> tuple[str, str]:
    r = await client.post("/api/v1/repositories", headers=headers, json={"provider": "local", "local_path": "vulnerable-app"})
    repo_id = r.json()["id"]
    async with database.async_session_maker() as db:
        repo = await db.get(Repository, uuid.UUID(repo_id))
        f = Finding(organization_id=repo.organization_id, repository_id=repo.id, fingerprint=uuid.uuid4().hex, scanner_name="semgrep",
                    finding_type="sast", title="Eval injection", severity="HIGH", file_path="src/app.py", start_line=36)
        db.add(f)
        await db.flush()
        p = RemediationProposal(organization_id=repo.organization_id, finding_id=f.id, title="guidance", remediation_type="guidance")
        db.add(p)
        await db.commit()
        return str(f.id), str(p.id)


async def test_finding_status_requires_reason_and_is_audited(client):
    h = await register(client, "dave")
    fid, _ = await _seed_finding(h, client)
    r = await client.patch(f"/api/v1/findings/{fid}", headers=h, json={"status": "FALSE_POSITIVE"})
    assert r.status_code == 422
    r = await client.patch(f"/api/v1/findings/{fid}", headers=h, json={"status": "FALSE_POSITIVE", "reason": "test fixture"})
    assert r.status_code == 200 and r.json()["status"] == "FALSE_POSITIVE"
    audit = (await client.get("/api/v1/organizations/current/audit?action=finding", headers=h)).json()
    assert audit["items"][0]["details"]["reason"] == "test fixture"


async def test_guidance_only_proposal_cannot_be_approved_or_verified(client):
    h = await register(client, "erin")
    _, pid = await _seed_finding(h, client)
    r = await client.post(f"/api/v1/remediation/proposals/{pid}/decision", headers=h, json={"decision": "approved"})
    assert r.status_code == 422
    r = await client.post(f"/api/v1/remediation/proposals/{pid}/verify", headers=h)
    assert r.status_code == 422
    r = await client.post(f"/api/v1/remediation/proposals/{pid}/pull-request", headers=h)
    assert r.status_code == 422


async def test_mcp_registry_rejects_arbitrary_commands_and_denies_unlisted_tools(client):
    h = await register(client, "frank")
    r = await client.post("/api/v1/mcp/integrations", headers=h, json={"name": "evil", "url": "http://example.com/mcp"})
    assert r.status_code == 422
    r = await client.post("/api/v1/mcp/integrations", headers=h, json={"name": "evil2"})
    assert r.status_code == 422
    integ = (await client.get("/api/v1/mcp/integrations", headers=h)).json()
    assert integ[0]["name"] == "trace-security" and integ[0]["is_builtin"]
    async with database.async_session_maker() as db:
        tool = MCPTool(integration_id=uuid.UUID(integ[0]["id"]), name="dangerous_write", is_allowed=False, sensitivity="write", requires_approval=True)
        db.add(tool)
        await db.commit()
        tid = str(tool.id)
    r = await client.post(f"/api/v1/mcp/tools/{tid}/execute", headers=h, json={"arguments": {}})
    assert r.status_code == 403 and "allowlist" in r.json()["detail"]
    await client.patch(f"/api/v1/mcp/tools/{tid}", headers=h, json={"is_allowed": True})
    r = await client.post(f"/api/v1/mcp/tools/{tid}/execute", headers=h, json={"arguments": {}})
    assert r.status_code == 403 and "approval" in r.json()["detail"]
    log = (await client.get("/api/v1/mcp/executions", headers=h)).json()
    assert [e["status"] for e in log["items"]] == ["denied", "denied"]


async def test_viewer_cannot_mutate(client):
    owner = await register(client, "grace")
    viewer = await register(client, "heidi")
    r = await client.post("/api/v1/organizations/current/members", headers=owner, json={"email": "heidi@example.com", "role": "viewer"})
    assert r.status_code == 201
    org_id = (await client.get("/api/v1/auth/me", headers=owner)).json()["organizations"][0]["id"]
    vh = {**viewer, "X-Organization-Id": org_id}
    assert (await client.get("/api/v1/repositories", headers=vh)).status_code == 200
    r = await client.post("/api/v1/repositories", headers=vh, json={"provider": "local", "local_path": "vulnerable-app"})
    assert r.status_code == 403


async def test_dashboard_and_reports_render(client):
    h = await register(client, "ivan")
    await _seed_finding(h, client)
    s = (await client.get("/api/v1/dashboard/summary", headers=h)).json()
    assert s["open_findings"] == 1 and s["data_scope"]["demo_data_present"] is False
    assert (await client.get("/api/v1/dashboard/trends?days=7", headers=h)).status_code == 200
    five_h = (await client.get("/api/v1/dashboard/trends?hours=5", headers=h)).json()["series"]
    assert len(five_h) == 21 and "T" in five_h[0]["date"]  # 15-minute points
    assert five_h[-1]["HIGH"] == 1
    assert len((await client.get("/api/v1/dashboard/trends?hours=24", headers=h)).json()["series"]) == 25  # hourly
    rep = await client.get("/api/v1/reports/executive?format=pdf", headers=h)
    assert rep.status_code == 200 and rep.content.startswith(b"%PDF")
    j = (await client.get("/api/v1/reports/executive", headers=h)).json()
    assert j["open_findings"] == 1
