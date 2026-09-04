"""One runtime configuration contract for UI, gateway and scan intelligence."""
from __future__ import annotations

from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from app.core.config import settings
from app.intelligence.llm_client import LLMClient, llm_client


class AIConfigRequest(BaseModel):
    provider: str | None = None
    base_url: str | None = None
    api_key: str | None = None
    clear_api_key: bool = False
    model: str | None = None
    routing_mode: Literal["auto", "single", "router_combo", "task_router"] | None = None
    enabled: bool | None = None
    llm_enabled: bool | None = None
    temperature: float | None = Field(default=None, ge=0, le=2)
    expected_revision: int | None = None


_revision = 0


def candidate_client(body: AIConfigRequest | None = None) -> LLMClient:
    body = body or AIConfigRequest()
    base = (body.base_url if body.base_url is not None else llm_client.base_url).strip().rstrip("/")
    parsed = urlsplit(base)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Base URL harus berupa URL HTTP(S) tanpa kredensial, query, atau fragment.")
    provider = (body.provider or settings.llm_provider).strip()
    provider = "ninerouter" if provider == "nine_router" else provider
    previous_provider = "ninerouter" if settings.llm_provider == "nine_router" else settings.llm_provider
    same_endpoint = base == llm_client.base_url and provider == previous_provider
    key = (body.api_key or "").strip()
    if not key and not body.clear_api_key and same_endpoint:
        key = llm_client.api_key
    model = (body.model if body.model is not None else llm_client.model).strip()
    mode = body.routing_mode or ("auto" if body.model is not None else llm_client.routing_mode)
    if not model and mode != "task_router":
        raise ValueError("Pilih atau masukkan ID model/combo terlebih dahulu.")
    candidate = LLMClient(base_url=base, api_key=key, model=model or "combo", provider=provider,
                          routing_mode=mode, temperature=body.temperature)
    return candidate


def public_config() -> dict:
    from app.ai.gateway import ai_gateway
    return {
        "status": "success", "enabled": settings.llm_enabled, "llm_enabled": settings.llm_enabled,
        "provider": settings.llm_provider, "base_url": llm_client.base_url, "model": llm_client.model,
        "routing_mode": llm_client.effective_routing_mode, "revision": _revision,
        "api_key_configured": bool(llm_client.api_key), "api_key_masked": "***" if llm_client.api_key else "",
        "is_configured": llm_client.is_configured, "active_provider": type(ai_gateway._provider).__name__,
        "persistence": "runtime_only",
    }


def apply_runtime_config(body: AIConfigRequest) -> dict:
    global _revision
    from app.ai.gateway import ai_gateway
    if body.expected_revision is not None and body.expected_revision != _revision:
        raise RuntimeError("Konfigurasi berubah di sesi lain. Muat ulang sebelum menyimpan.")
    candidate = candidate_client(body)  # Validate everything before mutating shared state.
    enabled = body.llm_enabled if body.llm_enabled is not None else body.enabled
    if enabled is not None:
        settings.llm_enabled = enabled
    for field, value in {
        "provider": candidate.provider, "base_url": candidate.base_url, "api_key": candidate.api_key,
        "model": candidate.model, "routing_mode": candidate.routing_mode, "temperature": candidate.temperature,
    }.items():
        setattr(settings, "llm_" + field, value)
        setattr(llm_client, field, value)
    llm_client._payload_cache.clear()
    llm_client._js_cache.clear()
    ai_gateway.apply_config({"provider": candidate.provider, "base_url": candidate.base_url,
                             "api_key": candidate.api_key, "model": candidate.model,
                             "routing_mode": candidate.routing_mode, "enabled": settings.llm_enabled})
    _revision += 1
    return public_config()


async def catalog_response(body: AIConfigRequest | None = None) -> dict:
    candidate = candidate_client(body)
    try:
        entries = await candidate.model_catalog()
        return {"status": "success", "models": [row["id"] for row in entries], "entries": entries,
                "source": "provider", "base_url": candidate.base_url}
    except Exception as exc:
        return {"status": "unavailable", "models": [], "entries": [], "source": "provider",
                "message": f"Katalog model tidak tersedia ({type(exc).__name__}); tidak ada model cadangan yang diasumsikan."}


async def test_candidate(body: AIConfigRequest | None = None) -> dict:
    candidate = candidate_client(body)
    # A primary-route test must not succeed through an unrelated Hermes server.
    candidate.hermes_base_url = ""
    result = await candidate.test_connection()
    result["status"] = "success" if result["status"] == "connected" else "error"
    result["candidate_only"] = True
    return result
