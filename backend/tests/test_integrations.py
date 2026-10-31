"""UI-managed integrations: storage, secrecy, verification, org isolation, env fallback and feature gating."""

import uuid

import httpx
import pytest
from sqlalchemy import select

from app.core import database
from app.core.config import settings
from app.db.models import OrgIntegration
from app.integrations import registry
from app.integrations.github import org_token
from app.llm.provider import AnthropicProvider, NoneProvider, OllamaProvider

from .conftest import register

pytestmark = pytest.mark.asyncio

_RealAsyncClient = httpx.AsyncClient


def mock_http(monkeypatch, handler):
    """Route every httpx.AsyncClient (provider health checks, GitHub, Langfuse) through `handler`."""
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _RealAsyncClient(*a, **{**k, "transport": httpx.MockTransport(handler)}))


def ollama_ok(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/api/tags":
        return httpx.Response(200, json={"models": [{"name": "qwen2.5-coder:7b"}, {"name": "llama3.1:8b"}]})
    return httpx.Response(404)


async def _org_id(client, h) -> str:
    return (await client.get("/api/v1/auth/me", headers=h)).json()["organizations"][0]["id"]


async def test_list_shows_every_integration_unconfigured(client):
    h = await register(client, "int-list")
    items = {i["kind"]: i for i in (await client.get("/api/v1/integrations", headers=h)).json()}
    assert set(items) == {"model_provider", "github", "langfuse"}
    mp = items["model_provider"]
    assert mp["configured"] is False and mp["ready"] is False and mp["status"] == "not_configured"
    assert mp["optional"] is False and "AI investigations" in mp["required_for"]
    assert {f["name"] for f in mp["fields"]} >= {"provider", "base_url", "model", "api_key"}


async def test_ai_features_are_gated_until_configured(client):
    h = await register(client, "int-gate")
    r = await client.post("/api/v1/evaluations/datasets", headers=h, json={
        "name": "gate check", "task_type": "cve_matching",
        "cases": [{"case_key": "c1", "input": {"ecosystem": "PyPI", "package": "pyyaml", "version": "5.3"}, "expected": {"cve_any": []}}]})
    ds_id = r.json()["id"]
    r = await client.post("/api/v1/evaluations/runs", headers=h, json={"dataset_id": ds_id, "modes": ["base"]})
    assert r.status_code == 409
    d = r.json()["detail"]
    assert d["code"] == "integration_required" and d["integration"] == "model_provider" and d["title"] == "Model provider"
    r = await client.post("/api/v1/ai-security/assessments", headers=h, json={"name": "probe it", "target_type": "llm_endpoint"})
    assert r.status_code == 409 and r.json()["detail"]["integration"] == "model_provider"


async def test_save_verifies_and_never_returns_secrets(client, monkeypatch):
    h = await register(client, "int-save")

    def anthropic(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-api-key"] == "sk-ant-test-secret-9876"
        return httpx.Response(200, json={"data": [{"id": "claude-sonnet-5-5"}, {"id": "claude-haiku-5-5"}]})

    mock_http(monkeypatch, anthropic)
    r = await client.put("/api/v1/integrations/model_provider", headers=h,
                         json={"config": {"provider": "anthropic", "model": "claude-sonnet-5-5", "allow_source": True},
                               "secrets": {"api_key": "sk-ant-test-secret-9876"}})
    assert r.status_code == 200, r.text
    body = r.json()
    assert "sk-ant-test-secret" not in r.text
    assert body["ready"] and body["status"] == "ok" and body["source"] == "organization"
    assert body["secrets"]["api_key"] == {"set": True, "last4": "9876"}
    assert "claude-haiku-5-5" in body["details"]["available_models"]
    assert "base_url" not in body["config"]  # not applicable to anthropic

    # stored encrypted
    async with database.async_session_maker() as db:
        row = (await db.execute(select(OrgIntegration).where(OrgIntegration.organization_id == uuid.UUID(await _org_id(client, h))))).scalar_one()
        assert "sk-ant-test-secret" not in str(row.secrets)
        p = await registry.resolve_provider(db, row.organization_id)
    assert isinstance(p, AnthropicProvider) and p.api_key == "sk-ant-test-secret-9876" and p.may_receive_source

    # blank secret keeps the stored key; a model change re-verifies
    r = await client.put("/api/v1/integrations/model_provider", headers=h,
                         json={"config": {"provider": "anthropic", "model": "claude-haiku-5-5"}, "secrets": {"api_key": ""}})
    assert r.json()["ready"] and r.json()["config"]["model"] == "claude-haiku-5-5" and r.json()["config"]["allow_source"] is False


async def test_failed_verification_is_saved_but_blocks_features(client, monkeypatch):
    h = await register(client, "int-fail")
    mock_http(monkeypatch, lambda req: httpx.Response(401, json={"error": "bad key"}))
    r = await client.put("/api/v1/integrations/model_provider", headers=h,
                         json={"config": {"provider": "anthropic", "model": "claude-sonnet-5-5"}, "secrets": {"api_key": "sk-ant-wrong-key"}})
    assert r.status_code == 200
    assert r.json()["status"] == "error" and r.json()["ready"] is False and "rejected" in r.json()["status_message"]
    r = await client.post("/api/v1/ai-security/assessments", headers=h, json={"name": "probe it", "target_type": "llm_endpoint"})
    assert r.status_code == 409 and "failed verification" in r.json()["detail"]["message"] and r.json()["detail"]["status"] == "error"


async def test_model_missing_lists_available_models(client, monkeypatch):
    h = await register(client, "int-missing")
    mock_http(monkeypatch, ollama_ok)
    r = await client.put("/api/v1/integrations/model_provider", headers=h,
                         json={"config": {"provider": "ollama", "base_url": "http://ollama.test:11434/", "model": "not-pulled"}})
    b = r.json()
    assert b["status"] == "error" and "llama3.1:8b" in b["status_message"]
    assert b["config"]["base_url"] == "http://ollama.test:11434"  # normalized
    r = await client.put("/api/v1/integrations/model_provider", headers=h,
                         json={"config": {"provider": "ollama", "base_url": "http://ollama.test:11434", "model": "llama3.1:8b"}})
    assert r.json()["ready"]
    async with database.async_session_maker() as db:
        p = await registry.resolve_provider(db, uuid.UUID(await _org_id(client, h)))
    assert isinstance(p, OllamaProvider) and p.base_url == "http://ollama.test:11434" and p.model == "llama3.1:8b"


async def test_validation_errors(client):
    h = await register(client, "int-valid")
    cases = [
        ({"provider": "ollama", "base_url": "http://x:1"}, {}, "Model is required"),
        ({"provider": "anthropic", "model": "m"}, {}, "API key is required"),
        ({"provider": "ollama", "base_url": "file:///etc/passwd", "model": "m"}, {}, "http(s) URL"),
        ({"provider": "gpt-magic", "model": "m"}, {}, "must be one of"),
    ]
    for config, secrets, msg in cases:
        r = await client.put("/api/v1/integrations/model_provider", headers=h, json={"config": config, "secrets": secrets})
        assert r.status_code == 422 and msg in r.json()["detail"], (config, r.text)
    assert (await client.put("/api/v1/integrations/nope", headers=h, json={})).status_code == 404


async def test_switching_provider_drops_stale_secret(client, monkeypatch):
    h = await register(client, "int-switch")
    mock_http(monkeypatch, lambda req: httpx.Response(200, json={"data": []}) if "anthropic" in str(req.url) else ollama_ok(req))
    await client.put("/api/v1/integrations/model_provider", headers=h,
                     json={"config": {"provider": "anthropic", "model": "claude-sonnet-5-5"}, "secrets": {"api_key": "sk-ant-abcdefgh"}})
    r = await client.put("/api/v1/integrations/model_provider", headers=h,
                         json={"config": {"provider": "ollama", "base_url": "http://ollama.test:11434", "model": "qwen2.5-coder:7b"}})
    assert r.json()["secrets"] == {} and r.json()["ready"]


async def test_dry_run_test_does_not_save(client, monkeypatch):
    h = await register(client, "int-dry")
    mock_http(monkeypatch, ollama_ok)
    r = await client.post("/api/v1/integrations/model_provider/verify", headers=h,
                          json={"config": {"provider": "ollama", "base_url": "http://ollama.test:11434", "model": "qwen2.5-coder:7b"}})
    assert r.status_code == 200 and r.json()["ok"] is True and r.json()["saved"] is False
    assert (await client.get("/api/v1/integrations/model_provider", headers=h)).json()["configured"] is False
    # re-verify with nothing configured -> setup prompt
    r = await client.post("/api/v1/integrations/model_provider/verify", headers=h)
    assert r.status_code == 409


async def test_reverify_records_result(client, monkeypatch):
    h = await register(client, "int-reverify")
    mock_http(monkeypatch, ollama_ok)
    await client.put("/api/v1/integrations/model_provider", headers=h,
                     json={"config": {"provider": "ollama", "base_url": "http://ollama.test:11434", "model": "qwen2.5-coder:7b"}})
    mock_http(monkeypatch, lambda req: (_ for _ in ()).throw(httpx.ConnectError("down")))
    r = await client.post("/api/v1/integrations/model_provider/verify", headers=h)
    assert r.json()["ok"] is False and r.json()["saved"] is True and "Could not reach" in r.json()["message"]
    assert (await client.get("/api/v1/integrations/model_provider", headers=h)).json()["ready"] is False


async def test_members_can_read_but_only_admins_can_change(client):
    owner = await register(client, "int-owner")
    member = await register(client, "int-member")
    await client.post("/api/v1/organizations/current/members", headers=owner, json={"email": "int-member@example.com", "role": "member"})
    mh = {**member, "X-Organization-Id": await _org_id(client, owner)}
    assert (await client.get("/api/v1/integrations", headers=mh)).status_code == 200
    body = {"config": {"provider": "ollama", "base_url": "http://x:1", "model": "m"}}
    assert (await client.put("/api/v1/integrations/model_provider", headers=mh, json=body)).status_code == 403
    assert (await client.post("/api/v1/integrations/model_provider/verify", headers=mh, json=body)).status_code == 403
    assert (await client.delete("/api/v1/integrations/model_provider", headers=mh)).status_code == 403


async def test_org_isolation_and_delete(client, monkeypatch):
    a = await register(client, "int-iso-a")
    b = await register(client, "int-iso-b")
    mock_http(monkeypatch, ollama_ok)
    await client.put("/api/v1/integrations/model_provider", headers=a,
                     json={"config": {"provider": "ollama", "base_url": "http://ollama.test:11434", "model": "qwen2.5-coder:7b"}})
    assert (await client.get("/api/v1/integrations/model_provider", headers=b)).json()["configured"] is False
    assert (await client.delete("/api/v1/integrations/model_provider", headers=b)).status_code == 404
    assert (await client.delete("/api/v1/integrations/model_provider", headers=a)).json() == {"ok": True}
    assert (await client.get("/api/v1/integrations/model_provider", headers=a)).json()["configured"] is False
    actions = [x["action"] for x in (await client.get("/api/v1/organizations/current/audit", headers=a)).json()["items"]]
    assert "integration.save" in actions and "integration.delete" in actions


async def test_github_token_verify_and_resolution(client, monkeypatch):
    h = await register(client, "int-gh")
    org_id = uuid.UUID(await _org_id(client, h))

    def gh(request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization") == "token ghp_goodtoken1234":
            return httpx.Response(200, json={"login": "octo"}, headers={"x-oauth-scopes": "repo"})
        return httpx.Response(401, json={"message": "Bad credentials"})

    mock_http(monkeypatch, gh)
    r = await client.put("/api/v1/integrations/github", headers=h, json={"secrets": {"token": "ghp_badtoken0000"}})
    assert r.json()["status"] == "error" and "401" in r.json()["status_message"]
    async with database.async_session_maker() as db:
        assert await org_token(db, org_id) is None  # a failed token is not used, and env is not consulted
    r = await client.put("/api/v1/integrations/github", headers=h, json={"secrets": {"token": "ghp_goodtoken1234"}})
    assert r.json()["ready"] and r.json()["status_message"] == "Authenticated as octo"
    async with database.async_session_maker() as db:
        assert await org_token(db, org_id) == "ghp_goodtoken1234"


async def test_langfuse_attaches_tracing(client, monkeypatch):
    h = await register(client, "int-lf")
    mock_http(monkeypatch, lambda req: httpx.Response(200, json={"data": [{"name": "trace-prod"}]}))
    r = await client.put("/api/v1/integrations/langfuse", headers=h,
                         json={"config": {"public_key": "pk-lf-1"}, "secrets": {"secret_key": "sk-lf-1"}})
    assert r.json()["ready"] and r.json()["config"]["host"] == "https://cloud.langfuse.com" and "trace-prod" in r.json()["status_message"]
    async with database.async_session_maker() as db:
        p = await registry.resolve_provider(db, uuid.UUID(await _org_id(client, h)))
    assert isinstance(p, NoneProvider)  # no model configured
    assert p.tracing == {"host": "https://cloud.langfuse.com", "public_key": "pk-lf-1", "secret_key": "sk-lf-1"}


async def test_env_fallback(client, monkeypatch):
    h = await register(client, "int-env")
    monkeypatch.setattr(settings, "GITHUB_TOKEN", "ghp_from_env_1234")
    monkeypatch.setattr(settings, "INTEGRATIONS_ENV_FALLBACK", True)
    gh = (await client.get("/api/v1/integrations/github", headers=h)).json()
    assert gh["source"] == "environment" and gh["ready"] and gh["secrets"] == {"token": {"set": True, "last4": None}}
    assert "ghp_from_env" not in str(gh)
    monkeypatch.setattr(settings, "INTEGRATIONS_ENV_FALLBACK", False)
    gh = (await client.get("/api/v1/integrations/github", headers=h)).json()
    assert gh["configured"] is False and gh["env_fallback"] is False


async def test_env_fallback_defaults_off_in_production(monkeypatch):
    monkeypatch.setattr(settings, "INTEGRATIONS_ENV_FALLBACK", None)
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    assert settings.env_integrations_enabled is False
    monkeypatch.setattr(settings, "ENVIRONMENT", "development")
    assert settings.env_integrations_enabled is True


async def test_org_provider_cannot_be_redirected_by_request(client, monkeypatch):
    h = await register(client, "int-redirect")
    mock_http(monkeypatch, ollama_ok)
    await client.put("/api/v1/integrations/model_provider", headers=h,
                     json={"config": {"provider": "ollama", "base_url": "http://ollama.test:11434", "model": "qwen2.5-coder:7b"}})
    async with database.async_session_maker() as db:
        p = await registry.resolve_provider(db, uuid.UUID(await _org_id(client, h)), "anthropic", "llama3.1:8b")
    assert isinstance(p, OllamaProvider) and p.model == "llama3.1:8b"


async def test_auto_investigate_scan_is_gated(client):
    h = await register(client, "int-autoinv")
    repo = (await client.post("/api/v1/repositories", headers=h, json={"provider": "local", "local_path": "vulnerable-app"})).json()
    r = await client.post("/api/v1/scans", headers=h, json={"repository_id": repo["id"], "auto_investigate": True})
    assert r.status_code == 409 and r.json()["detail"]["integration"] == "model_provider"
