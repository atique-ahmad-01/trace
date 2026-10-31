"""
UI-managed integrations.

Each organization configures its external services (model provider, GitHub token, Langfuse)
in Settings -> Integrations. Values are stored per org in `org_integrations`; secret fields
are Fernet-encrypted and never returned by the API. Saving runs a live verification.

Resolution order for an org: its own saved integration, then (when
settings.env_integrations_enabled) the environment variables, then nothing. Features that
need an integration call `require()`, which raises a 409 the frontend turns into a
"set this up first" prompt that links to the settings page and back.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import decrypt_secret, encrypt_secret
from app.db.models import OrgIntegration
from app.llm.provider import (AnthropicProvider, BaseProvider, NoneProvider, OllamaProvider, OpenAICompatibleProvider,
                              get_provider)

HOSTED_MODEL_PROVIDERS = ["anthropic", "openai_compatible"]

# Field schema drives validation here and the form in the UI.
# type: select | text | url | secret | bool. show_if: {field: [values]} limits a field to some choices.
DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "model_provider": {
        "title": "Model provider",
        "description": "The LLM used by AI investigations, evaluations and LLM-endpoint assessments.",
        "required_for": ["AI investigations", "Evaluations", "LLM endpoint assessments"],
        "optional": False,
        "fields": [
            {"name": "provider", "label": "Provider", "type": "select", "required": True, "default": "ollama",
             "options": [{"value": "ollama", "label": "Ollama (local)"},
                         {"value": "openai_compatible", "label": "OpenAI-compatible (vLLM, OpenAI, …)"},
                         {"value": "anthropic", "label": "Anthropic Claude"}]},
            {"name": "base_url", "label": "Base URL", "type": "url", "required": True, "show_if": {"provider": ["ollama", "openai_compatible"]},
             "placeholder": "http://localhost:11434", "help": "Ollama server URL, or the /v1 root of an OpenAI-compatible API."},
            {"name": "api_key", "label": "API key", "type": "secret", "required": True, "show_if": {"provider": ["anthropic"]},
             "placeholder": "sk-ant-…"},
            {"name": "api_key", "label": "API key", "type": "secret", "required": False, "show_if": {"provider": ["openai_compatible"]},
             "placeholder": "optional for self-hosted endpoints"},
            {"name": "model", "label": "Model", "type": "text", "required": True, "placeholder": "qwen2.5-coder:7b",
             "help": "Verify lists the models the endpoint offers."},
            {"name": "hosted", "label": "Third-party hosted endpoint", "type": "bool", "default": False, "show_if": {"provider": ["openai_compatible"]},
             "help": "Treat the endpoint as hosted: repository source code is withheld unless allowed below."},
            {"name": "allow_source", "label": "Allow repository source code to be sent to this hosted model", "type": "bool", "default": False,
             "show_if": {"provider": HOSTED_MODEL_PROVIDERS}},
        ],
    },
    "github": {
        "title": "GitHub",
        "description": "Personal access token for private repositories, branch listing and opening fix pull requests "
                       "(used when no GitHub App installation covers the repository).",
        "required_for": ["Pull requests", "Private repositories"],
        "optional": True,
        "fields": [
            {"name": "token", "label": "Access token", "type": "secret", "required": True, "placeholder": "github_pat_…",
             "help": "Fine-grained token with Contents (read/write) and Pull requests (write) on the selected repositories."},
        ],
    },
    "langfuse": {
        "title": "Langfuse",
        "description": "Optional LLM observability: token usage and latency for every model call (metadata only).",
        "required_for": [],
        "optional": True,
        "fields": [
            {"name": "host", "label": "Host", "type": "url", "required": True, "default": "https://cloud.langfuse.com"},
            {"name": "public_key", "label": "Public key", "type": "text", "required": True, "placeholder": "pk-lf-…"},
            {"name": "secret_key", "label": "Secret key", "type": "secret", "required": True, "placeholder": "sk-lf-…"},
        ],
    },
}

KINDS = list(DEFINITIONS)


def _iso(v: datetime) -> str:
    # Same as app.api.common.iso; importing app.api from here would be circular (endpoints import this module).
    return (v if v.tzinfo else v.replace(tzinfo=timezone.utc)).isoformat()


class IntegrationRequired(HTTPException):
    """409 with a machine-readable detail; the frontend opens the setup prompt for `integration`."""

    def __init__(self, kind: str, message: Optional[str] = None, status: Optional[str] = None):
        title = DEFINITIONS[kind]["title"]
        super().__init__(409, {
            "code": "integration_required", "integration": kind, "title": title, "status": status or "not_configured",
            "message": message or f"{title} is not configured for this organization. An admin can set it up in Settings → Integrations.",
        })


@dataclass
class Resolved:
    kind: str
    source: Optional[str] = None  # organization | environment | None
    config: Dict[str, Any] = field(default_factory=dict)
    secrets: Dict[str, str] = field(default_factory=dict)  # decrypted; never serialized
    status: str = "not_configured"  # not_configured | unverified | ok | error | environment
    status_message: Optional[str] = None
    row: Optional[OrgIntegration] = None

    @property
    def ready(self) -> bool:
        # A failed verification blocks use; an imported, never-verified credential keeps working until verified.
        return self.source == "environment" or (self.source == "organization" and self.status in ("ok", "unverified"))


def _fields(kind: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Fields that apply to this config (resolving show_if against the chosen values)."""
    out, seen = [], set()
    for f in DEFINITIONS[kind]["fields"]:
        cond = f.get("show_if") or {}
        if all(config.get(k, _default(kind, k)) in v for k, v in cond.items()) and f["name"] not in seen:
            out.append(f)
            seen.add(f["name"])
    return out


def _default(kind: str, name: str) -> Any:
    return next((f.get("default") for f in DEFINITIONS[kind]["fields"] if f["name"] == name), None)


def _env(kind: str) -> Optional[Tuple[Dict[str, Any], Dict[str, str]]]:
    """Environment-variable configuration, if meaningfully set."""
    s = settings
    if kind == "model_provider":
        if s.MODEL_PROVIDER == "ollama":
            return {"provider": "ollama", "base_url": s.OLLAMA_BASE_URL, "model": s.OLLAMA_MODEL}, {}
        if s.MODEL_PROVIDER == "openai_compatible" and s.OPENAI_COMPATIBLE_BASE_URL and s.OPENAI_COMPATIBLE_MODEL:
            return ({"provider": "openai_compatible", "base_url": s.OPENAI_COMPATIBLE_BASE_URL, "model": s.OPENAI_COMPATIBLE_MODEL,
                     "hosted": False, "allow_source": s.ALLOW_SOURCE_TO_HOSTED_LLM},
                    {"api_key": s.OPENAI_COMPATIBLE_API_KEY} if s.OPENAI_COMPATIBLE_API_KEY else {})
        if s.MODEL_PROVIDER == "anthropic" and s.ANTHROPIC_API_KEY:
            return {"provider": "anthropic", "model": s.ANTHROPIC_MODEL, "allow_source": s.ALLOW_SOURCE_TO_HOSTED_LLM}, {"api_key": s.ANTHROPIC_API_KEY}
        return None
    if kind == "github":
        return ({}, {"token": s.GITHUB_TOKEN}) if s.GITHUB_TOKEN else None
    if kind == "langfuse":
        if s.LANGFUSE_PUBLIC_KEY and s.LANGFUSE_SECRET_KEY:
            return {"host": s.LANGFUSE_HOST, "public_key": s.LANGFUSE_PUBLIC_KEY}, {"secret_key": s.LANGFUSE_SECRET_KEY}
        return None
    return None


async def _row(db: AsyncSession, org_id, kind: str) -> Optional[OrgIntegration]:
    return (await db.execute(select(OrgIntegration).where(OrgIntegration.organization_id == org_id, OrgIntegration.kind == kind))).scalar_one_or_none()


def _decrypt_all(row: OrgIntegration) -> Dict[str, str]:
    out = {}
    for name, item in (row.secrets or {}).items():
        val = decrypt_secret((item or {}).get("value"))
        if val:
            out[name] = val
    return out


async def resolve(db: AsyncSession, org_id, kind: str) -> Resolved:
    row = await _row(db, org_id, kind)
    if row:
        return Resolved(kind, "organization", dict(row.config or {}), _decrypt_all(row), row.status, row.status_message, row)
    env = _env(kind) if settings.env_integrations_enabled else None
    if env:
        return Resolved(kind, "environment", env[0], env[1], "environment", "Using server environment variables")
    return Resolved(kind)


async def require(db: AsyncSession, org_id, kind: str) -> Resolved:
    r = await resolve(db, org_id, kind)
    if r.ready:
        return r
    if r.source == "organization":
        raise IntegrationRequired(kind, f"{DEFINITIONS[kind]['title']} failed verification: {r.status_message or 'unknown error'}. "
                                        "Fix it in Settings → Integrations.", status=r.status)
    raise IntegrationRequired(kind)


# --------------------------------------------------------------------------- providers


def build_provider(config: Dict[str, Any], secrets: Dict[str, str], model: Optional[str] = None) -> BaseProvider:
    name, model = config.get("provider"), model or config.get("model")
    if name == "ollama":
        p: BaseProvider = OllamaProvider(model, base_url=config.get("base_url") or settings.OLLAMA_BASE_URL)
    elif name == "openai_compatible":
        p = OpenAICompatibleProvider(model, base_url=config.get("base_url"), api_key=secrets.get("api_key"), hosted=bool(config.get("hosted")))
    elif name == "anthropic":
        p = AnthropicProvider(model, api_key=secrets.get("api_key"))
    else:
        return NoneProvider()
    p.allow_source = bool(config.get("allow_source"))
    return p


async def resolve_provider(db: AsyncSession, org_id, name: Optional[str] = None, model: Optional[str] = None) -> BaseProvider:
    """The org's model provider; `model` overrides the configured model. An org that configured its own
    provider always uses it (admins choose it, a request cannot redirect it). Only in env-fallback mode can
    a request pick another env-configured provider by `name`, as before UI-managed integrations."""
    r = await resolve(db, org_id, "model_provider")
    if r.source != "organization" and name and name != r.config.get("provider"):
        p = get_provider(name, model) if settings.env_integrations_enabled else NoneProvider()
    elif r.ready:
        p = build_provider(r.config, r.secrets, model)
    else:
        p = NoneProvider()
    lf = await resolve(db, org_id, "langfuse")
    p.tracing = {"host": lf.config.get("host"), "public_key": lf.config.get("public_key"), "secret_key": lf.secrets.get("secret_key")} if lf.ready else {}
    return p


async def secret(db: AsyncSession, org_id, kind: str, name: str) -> Optional[str]:
    """A secret of a ready integration (e.g. the GitHub token), else None."""
    r = await resolve(db, org_id, kind)
    return r.secrets.get(name) if r.ready else None


# --------------------------------------------------------------------------- validation & storage


def validate(kind: str, config: Dict[str, Any], secrets_in: Dict[str, Optional[str]], existing: Optional[OrgIntegration]) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """Clean config/secrets against the schema. Blank secrets keep the stored value. Returns (config, new_secrets)."""
    if kind not in DEFINITIONS:
        raise HTTPException(404, "Unknown integration")
    merged = {**{f["name"]: f["default"] for f in DEFINITIONS[kind]["fields"] if "default" in f}, **(config or {})}
    fields = _fields(kind, merged)
    clean: Dict[str, Any] = {}
    new_secrets: Dict[str, str] = {}
    stored = set((existing.secrets or {}).keys()) if existing else set()
    errors = []
    for f in fields:
        n, t = f["name"], f["type"]
        if t == "secret":
            v = (secrets_in or {}).get(n)
            v = v.strip() if isinstance(v, str) else None
            if v:
                if len(v) > 4000:
                    errors.append(f"{f['label']} is too long")
                new_secrets[n] = v
            elif f.get("required") and n not in stored:
                errors.append(f"{f['label']} is required")
            continue
        v = merged.get(n)
        if t == "bool":
            clean[n] = bool(v)
            continue
        v = str(v).strip() if v is not None else ""
        if not v:
            if f.get("required"):
                errors.append(f"{f['label']} is required")
            continue
        if len(v) > 500:
            errors.append(f"{f['label']} is too long")
        if t == "select" and v not in [o["value"] for o in f["options"]]:
            errors.append(f"{f['label']} must be one of {', '.join(o['value'] for o in f['options'])}")
        if t == "url":
            u = urlparse(v)
            if u.scheme not in ("http", "https") or not u.netloc:
                errors.append(f"{f['label']} must be an http(s) URL")
            v = v.rstrip("/")
        clean[n] = v
    if errors:
        raise HTTPException(422, "; ".join(errors))
    return clean, new_secrets


def _secret_names(kind: str, config: Dict[str, Any]) -> set:
    return {f["name"] for f in _fields(kind, config) if f["type"] == "secret"}


async def save(db: AsyncSession, org_id, kind: str, config: Dict[str, Any], secrets_in: Dict[str, Optional[str]], user=None) -> OrgIntegration:
    row = await _row(db, org_id, kind)
    clean, new_secrets = validate(kind, config, secrets_in, row)
    if not row:
        row = OrgIntegration(organization_id=org_id, kind=kind, config={}, secrets={}, status="unverified")
        db.add(row)
    keep = _secret_names(kind, clean)  # drop secrets that no longer apply (e.g. switched provider)
    stored = {k: v for k, v in (row.secrets or {}).items() if k in keep}
    for n, v in new_secrets.items():
        stored[n] = {"value": encrypt_secret(v), "last4": v[-4:]}
    row.config, row.secrets = clean, stored
    row.updated_by = getattr(user, "id", None)
    await verify_row(row)
    await db.flush()
    return row


async def verify_row(row: OrgIntegration) -> OrgIntegration:
    ok, message, details = await verify(row.kind, dict(row.config or {}), _decrypt_all(row))
    row.status, row.status_message, row.details = ("ok" if ok else "error"), message, details
    row.verified_at = datetime.now(timezone.utc)
    return row


async def test_unsaved(db: AsyncSession, org_id, kind: str, config: Dict[str, Any], secrets_in: Dict[str, Optional[str]]) -> Tuple[bool, str, Dict[str, Any]]:
    """Verify a draft from the form without saving; blank secrets fall back to the stored ones."""
    row = await _row(db, org_id, kind)
    clean, new_secrets = validate(kind, config, secrets_in, row)
    secrets = {**(_decrypt_all(row) if row else {}), **new_secrets}
    return await verify(kind, clean, secrets)


# --------------------------------------------------------------------------- verification


async def verify(kind: str, config: Dict[str, Any], secrets: Dict[str, str]) -> Tuple[bool, str, Dict[str, Any]]:
    """Live check against the service. Returns (ok, human message, details)."""
    try:
        if kind == "model_provider":
            return await _verify_model(config, secrets)
        if kind == "github":
            return await _verify_github(secrets.get("token"))
        if kind == "langfuse":
            return await _verify_langfuse(config, secrets)
    except httpx.HTTPError as e:
        return False, f"Connection failed: {type(e).__name__}", {}
    return False, "Unknown integration", {}


_MODEL_STATUS = {
    "unreachable": "Could not reach the endpoint",
    "invalid_api_key": "The API key was rejected",
    "not_configured": "Missing base URL or API key",
    "model_missing": "Connected, but the model is not available on this endpoint",
}


async def _verify_model(config: Dict[str, Any], secrets: Dict[str, str]) -> Tuple[bool, str, Dict[str, Any]]:
    p = build_provider(config, secrets)
    h = await p.health()
    models = h.get("available_models") or []
    details = {"provider": p.name, "model": p.model, "available_models": models[:200], "hosted": p.hosted}
    st = h.get("status", "")
    if st == "ok":
        return True, f"Connected to {p.name} · model {p.model} available", details
    msg = _MODEL_STATUS.get(st) or (f"Endpoint returned HTTP {st[5:]}" if st.startswith("http_") else st or "verification failed")
    if h.get("error"):
        msg += f" ({h['error']})"
    if st == "model_missing" and models:
        msg += f". Available: {', '.join(models[:8])}{'…' if len(models) > 8 else ''}"
    return False, msg, details


async def _verify_github(token: Optional[str]) -> Tuple[bool, str, Dict[str, Any]]:
    if not token:
        return False, "No token provided", {}
    from app.integrations.github import _headers

    async with httpx.AsyncClient(base_url=settings.GITHUB_API_URL, timeout=15) as c:
        r = await c.get("/user", headers=_headers(token))
    if r.status_code == 401:
        return False, "GitHub rejected the token (401 Bad credentials)", {}
    if r.status_code >= 400:
        return False, f"GitHub returned HTTP {r.status_code}", {}
    login = r.json().get("login")
    scopes = r.headers.get("x-oauth-scopes")
    return True, f"Authenticated as {login}", {"login": login, "scopes": scopes}


async def _verify_langfuse(config: Dict[str, Any], secrets: Dict[str, str]) -> Tuple[bool, str, Dict[str, Any]]:
    host = (config.get("host") or "").rstrip("/")
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.get(f"{host}/api/public/projects", auth=(config.get("public_key") or "", secrets.get("secret_key") or ""))
    if r.status_code in (401, 403):
        return False, "Langfuse rejected the key pair", {}
    if r.status_code >= 400:
        return False, f"Langfuse returned HTTP {r.status_code}", {}
    projects = [p.get("name") for p in (r.json().get("data") or []) if p.get("name")]
    return True, f"Connected to Langfuse{' project ' + projects[0] if projects else ''}", {"projects": projects}


# --------------------------------------------------------------------------- serialization


def serialize(r: Resolved) -> Dict[str, Any]:
    d = DEFINITIONS[r.kind]
    hints = {k: {"set": True, "last4": (v or {}).get("last4")} for k, v in ((r.row.secrets if r.row else None) or {}).items()}
    if r.source == "environment":
        hints = {k: {"set": True, "last4": None} for k in r.secrets}
    row = r.row
    return {
        "kind": r.kind, "title": d["title"], "description": d["description"], "required_for": d["required_for"], "optional": d["optional"],
        "fields": d["fields"], "source": r.source, "configured": r.source is not None, "ready": r.ready,
        "status": r.status, "status_message": r.status_message, "config": r.config, "secrets": hints,
        "details": (row.details or {}) if row else {},
        "verified_at": _iso(row.verified_at) if row and row.verified_at else None,
        "updated_at": _iso(row.updated_at) if row and row.updated_at else None,
        "env_fallback": settings.env_integrations_enabled,
    }
