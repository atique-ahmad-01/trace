"""
Model provider abstraction.

Providers: ollama (local), openai_compatible (vLLM / any /v1/chat/completions), anthropic, none.
All providers return LLMResult with token usage and latency. `complete_json` requests
structured JSON output and validates it parses.

Data governance: hosted providers (anthropic, or an openai_compatible endpoint flagged
hosted) never receive repository source code unless ALLOW_SOURCE_TO_HOSTED_LLM=true;
callers check `provider.may_receive_source`.
"""

import base64
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx
from loguru import logger

from app.core.config import settings


class LLMUnavailable(Exception):
    pass


@dataclass
class LLMResult:
    text: str
    model: str
    provider: str
    tokens_in: int = 0
    tokens_out: int = 0
    latency_ms: int = 0
    data: Optional[Any] = None
    raw: Dict[str, Any] = field(default_factory=dict)


class BaseProvider:
    name = "base"
    hosted = False

    def __init__(self, model: Optional[str] = None):
        self.model = model or ""

    @property
    def may_receive_source(self) -> bool:
        return not self.hosted or settings.ALLOW_SOURCE_TO_HOSTED_LLM

    async def chat(self, messages: List[Dict[str, str]], *, json_mode: bool = False, temperature: Optional[float] = None,
                   max_tokens: Optional[int] = None) -> LLMResult:
        raise NotImplementedError

    async def health(self) -> Dict[str, Any]:
        raise NotImplementedError

    async def complete_json(self, system: str, user: str, *, temperature: Optional[float] = None, max_tokens: Optional[int] = None) -> LLMResult:
        msgs = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        res = await self.chat(msgs, json_mode=True, temperature=temperature, max_tokens=max_tokens)
        res.data = parse_json(res.text)
        if res.data is None:  # one repair attempt
            msgs += [{"role": "assistant", "content": res.text[:4000]}, {"role": "user", "content": "That was not valid JSON. Reply with only the JSON object."}]
            res2 = await self.chat(msgs, json_mode=True, temperature=0, max_tokens=max_tokens)
            res2.tokens_in += res.tokens_in
            res2.tokens_out += res.tokens_out
            res2.latency_ms += res.latency_ms
            res2.data = parse_json(res2.text)
            res = res2
        _trace(self, msgs, res)
        return res


def parse_json(text: str) -> Optional[Any]:
    text = re.sub(r"<think>.*?</think>", "", text or "", flags=re.S).strip()
    m = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if m:
        text = m.group(1)
    start = min([i for i in (text.find("{"), text.find("[")) if i >= 0], default=-1)
    if start < 0:
        return None
    for end in range(len(text), start, -1):
        if text[end - 1] in "}]":
            try:
                return json.loads(text[start:end])
            except json.JSONDecodeError:
                continue
    return None


class OllamaProvider(BaseProvider):
    name = "ollama"

    def __init__(self, model: Optional[str] = None, base_url: Optional[str] = None):
        super().__init__(model or settings.OLLAMA_MODEL)
        self.base_url = (base_url or settings.OLLAMA_BASE_URL).rstrip("/")

    async def chat(self, messages, *, json_mode=False, temperature=None, max_tokens=None) -> LLMResult:
        body: Dict[str, Any] = {
            "model": self.model, "messages": messages, "stream": False, "think": False,
            "options": {"temperature": settings.LLM_TEMPERATURE if temperature is None else temperature,
                        "num_predict": max_tokens or settings.LLM_MAX_TOKENS, "num_ctx": 8192},
        }
        if json_mode:
            body["format"] = "json"
        t = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=settings.LLM_TIMEOUT_SECONDS) as c:
                r = await c.post(f"{self.base_url}/api/chat", json=body)
                if r.status_code == 400 and "think" in r.text:
                    body.pop("think")
                    r = await c.post(f"{self.base_url}/api/chat", json=body)
        except httpx.HTTPError as e:
            raise LLMUnavailable(f"Ollama unreachable at {self.base_url}: {type(e).__name__}") from e
        if r.status_code >= 400:
            raise LLMUnavailable(f"Ollama error {r.status_code}: {r.text[:200]}")
        d = r.json()
        return LLMResult(text=d.get("message", {}).get("content", ""), model=self.model, provider=self.name,
                         tokens_in=d.get("prompt_eval_count", 0), tokens_out=d.get("eval_count", 0),
                         latency_ms=int((time.monotonic() - t) * 1000))

    async def health(self):
        try:
            async with httpx.AsyncClient(timeout=5) as c:
                r = await c.get(f"{self.base_url}/api/tags")
            models = [m["name"] for m in r.json().get("models", [])]
            return {"provider": self.name, "status": "ok" if self.model in models else "model_missing", "model": self.model,
                    "available_models": models, "hosted": False}
        except Exception as e:  # noqa: BLE001
            return {"provider": self.name, "status": "unreachable", "model": self.model, "error": type(e).__name__, "hosted": False}


class OpenAICompatibleProvider(BaseProvider):
    name = "openai_compatible"

    def __init__(self, model: Optional[str] = None, base_url: Optional[str] = None, api_key: Optional[str] = None, hosted: bool = False):
        super().__init__(model or settings.OPENAI_COMPATIBLE_MODEL)
        self.base_url = (base_url or settings.OPENAI_COMPATIBLE_BASE_URL or "").rstrip("/")
        self.api_key = api_key or settings.OPENAI_COMPATIBLE_API_KEY
        self.hosted = hosted

    async def chat(self, messages, *, json_mode=False, temperature=None, max_tokens=None) -> LLMResult:
        if not self.base_url or not self.model:
            raise LLMUnavailable("OPENAI_COMPATIBLE_BASE_URL / OPENAI_COMPATIBLE_MODEL not configured")
        body: Dict[str, Any] = {"model": self.model, "messages": messages,
                                "temperature": settings.LLM_TEMPERATURE if temperature is None else temperature,
                                "max_tokens": max_tokens or settings.LLM_MAX_TOKENS}
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        t = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=settings.LLM_TIMEOUT_SECONDS) as c:
                r = await c.post(f"{self.base_url}/chat/completions", json=body, headers=headers)
        except httpx.HTTPError as e:
            raise LLMUnavailable(f"OpenAI-compatible endpoint unreachable: {type(e).__name__}") from e
        if r.status_code >= 400:
            raise LLMUnavailable(f"OpenAI-compatible error {r.status_code}: {r.text[:200]}")
        d = r.json()
        u = d.get("usage") or {}
        return LLMResult(text=d["choices"][0]["message"].get("content") or "", model=self.model, provider=self.name,
                         tokens_in=u.get("prompt_tokens", 0), tokens_out=u.get("completion_tokens", 0),
                         latency_ms=int((time.monotonic() - t) * 1000))

    async def health(self):
        if not self.base_url:
            return {"provider": self.name, "status": "not_configured", "hosted": self.hosted}
        try:
            async with httpx.AsyncClient(timeout=5) as c:
                r = await c.get(f"{self.base_url}/models", headers={"Authorization": f"Bearer {self.api_key}"} if self.api_key else {})
            return {"provider": self.name, "status": "ok" if r.status_code < 400 else f"http_{r.status_code}", "model": self.model, "hosted": self.hosted}
        except Exception as e:  # noqa: BLE001
            return {"provider": self.name, "status": "unreachable", "error": type(e).__name__, "hosted": self.hosted}


class AnthropicProvider(BaseProvider):
    name = "anthropic"
    hosted = True

    def __init__(self, model: Optional[str] = None, api_key: Optional[str] = None):
        super().__init__(model or settings.ANTHROPIC_MODEL)
        self.api_key = api_key or settings.ANTHROPIC_API_KEY

    async def chat(self, messages, *, json_mode=False, temperature=None, max_tokens=None) -> LLMResult:
        if not self.api_key:
            raise LLMUnavailable("ANTHROPIC_API_KEY not configured")
        system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
        if json_mode:
            system += "\n\nRespond with a single valid JSON object and nothing else."
        msgs = [m for m in messages if m["role"] != "system"]
        body = {"model": self.model, "system": system, "messages": msgs, "max_tokens": max_tokens or settings.LLM_MAX_TOKENS,
                "temperature": settings.LLM_TEMPERATURE if temperature is None else temperature}
        t = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=settings.LLM_TIMEOUT_SECONDS) as c:
                r = await c.post("https://api.anthropic.com/v1/messages", json=body,
                                 headers={"x-api-key": self.api_key, "anthropic-version": "2023-06-01"})
        except httpx.HTTPError as e:
            raise LLMUnavailable(f"Anthropic API unreachable: {type(e).__name__}") from e
        if r.status_code >= 400:
            raise LLMUnavailable(f"Anthropic error {r.status_code}: {r.text[:200]}")
        d = r.json()
        text = "".join(b.get("text", "") for b in d.get("content", []) if b.get("type") == "text")
        u = d.get("usage") or {}
        return LLMResult(text=text, model=self.model, provider=self.name, tokens_in=u.get("input_tokens", 0),
                         tokens_out=u.get("output_tokens", 0), latency_ms=int((time.monotonic() - t) * 1000))

    async def health(self):
        return {"provider": self.name, "status": "configured" if self.api_key else "not_configured", "model": self.model, "hosted": True}


class NoneProvider(BaseProvider):
    name = "none"

    async def chat(self, *a, **k):
        raise LLMUnavailable("No model provider configured (MODEL_PROVIDER=none)")

    async def health(self):
        return {"provider": "none", "status": "disabled", "hosted": False}


def get_provider(name: Optional[str] = None, model: Optional[str] = None) -> BaseProvider:
    name = name or settings.MODEL_PROVIDER
    if name == "ollama":
        return OllamaProvider(model)
    if name == "openai_compatible":
        return OpenAICompatibleProvider(model)
    if name == "anthropic":
        return AnthropicProvider(model)
    return NoneProvider()


def estimate_cost(model: str, tokens_in: int, tokens_out: int) -> Optional[float]:
    """USD estimate from LLM_PRICING; None when the model has no configured price (e.g. local models = $0 compute not tracked)."""
    for entry in settings.LLM_PRICING.split(","):
        if "=" not in entry:
            continue
        m, price = entry.split("=", 1)
        if m.strip() == model:
            pin, pout = (float(x) for x in price.split("/"))
            return round(tokens_in / 1e6 * pin + tokens_out / 1e6 * pout, 6)
    return None


def _trace(provider: BaseProvider, messages, res: LLMResult) -> None:
    """Send a generation to Langfuse when configured (fire-and-forget, metadata only for hosted safety)."""
    if not (settings.LANGFUSE_PUBLIC_KEY and settings.LANGFUSE_SECRET_KEY):
        return
    try:
        auth = base64.b64encode(f"{settings.LANGFUSE_PUBLIC_KEY}:{settings.LANGFUSE_SECRET_KEY}".encode()).decode()
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        event = {"id": str(uuid.uuid4()), "type": "generation-create", "timestamp": now,
                 "body": {"id": str(uuid.uuid4()), "name": "trace-llm", "model": res.model, "startTime": now,
                          "usage": {"input": res.tokens_in, "output": res.tokens_out},
                          "metadata": {"provider": res.provider, "latency_ms": res.latency_ms}}}
        httpx.post(f"{settings.LANGFUSE_HOST}/api/public/ingestion", json={"batch": [event]},
                   headers={"Authorization": f"Basic {auth}"}, timeout=3)
    except Exception as e:  # noqa: BLE001
        logger.debug(f"langfuse trace failed: {e}")
