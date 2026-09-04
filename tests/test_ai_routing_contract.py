import asyncio
import json
from unittest.mock import AsyncMock

import httpx
import pytest

from app.intelligence.llm_client import LLMClient


def wire(monkeypatch, handler):
    real_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)
    monkeypatch.setattr("app.intelligence.llm_client.httpx.AsyncClient",
                        lambda **kwargs: real_client(transport=transport, **kwargs))


@pytest.mark.asyncio
@pytest.mark.parametrize("mode,model", [("single", "provider/exact"), ("router_combo", "security"), ("router_combo", "combo")])
async def test_exact_routes_never_silently_fallback(monkeypatch, mode, model):
    requests = []
    def handler(request):
        requests.append(json.loads(request.content)["model"])
        return httpx.Response(429)
    wire(monkeypatch, handler)
    client = LLMClient(base_url="http://localhost:1/v1", api_key="fixture", model=model, routing_mode=mode)
    client.hermes_base_url = "http://localhost:2/v1"
    client._chat_hermes = AsyncMock()
    with pytest.raises(RuntimeError):
        await client.chat([{"role": "user", "content": "fixture"}], timeout=2)
    assert requests == [model]
    client._chat_hermes.assert_not_called()


@pytest.mark.asyncio
async def test_task_routing_and_override_report_actual_route(monkeypatch):
    requested = []
    def handler(request):
        model = json.loads(request.content)["model"]
        requested.append(model)
        return httpx.Response(429) if model == "security" else httpx.Response(200, json={
            "model": "provider-reported", "choices": [{"message": {"content": "PENTEST_AI_READY"}}]})
    wire(monkeypatch, handler)
    client = LLMClient(base_url="http://localhost:1/v1", api_key="fixture", model="combo", routing_mode="task_router")
    client.hermes_base_url = ""
    trace = {}
    await client.chat([{"role": "user", "content": "fixture"}], task="reasoning", timeout=2, _trace=trace)
    assert requested == ["security", "developer"]
    assert trace["requested_model"] == "developer"
    assert trace["response_model"] == "provider-reported"
    await client.chat([{"role": "user", "content": "fixture"}], model="explicit/model", timeout=2)
    assert requested[-1] == "explicit/model"


@pytest.mark.asyncio
async def test_live_config_changes_do_not_retarget_inflight_cascade(monkeypatch):
    entered, release = asyncio.Event(), asyncio.Event()
    requests = []
    async def handler(request):
        requests.append((str(request.url), request.headers.get("authorization")))
        if len(requests) == 1:
            entered.set()
            await release.wait()
            return httpx.Response(429)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})
    wire(monkeypatch, handler)
    client = LLMClient(base_url="http://localhost:1/v1", api_key="original", model="combo", routing_mode="task_router")
    client.hermes_base_url = ""
    task = asyncio.create_task(client.chat([{"role": "user", "content": "fixture"}], timeout=3))
    await entered.wait()
    client.base_url, client.api_key, client.model = "http://localhost:2/v1", "changed", "new"
    release.set()
    await task
    assert requests == [("http://localhost:1/v1/chat/completions", "Bearer original")] * 2


@pytest.mark.asyncio
async def test_catalog_retains_combo_metadata_and_never_fabricates(monkeypatch):
    wire(monkeypatch, lambda request: httpx.Response(200, json={"data": [
        {"id": "my-combo", "owned_by": "combo"}, {"id": "provider/model", "owned_by": "provider"}]}))
    client = LLMClient(base_url="http://localhost:1/v1", api_key="fixture", model="provider/model")
    entries = await client.model_catalog()
    assert [row["kind"] for row in entries] == ["combo", "model"]
    monkeypatch.setattr(LLMClient, "model_catalog", AsyncMock(side_effect=ConnectionError))
    from app.ai.configuration import catalog_response, AIConfigRequest
    result = await catalog_response(AIConfigRequest(base_url="http://localhost:1/v1", model="fixture"))
    assert result["status"] == "unavailable"
    assert result["models"] == result["entries"] == []


@pytest.mark.asyncio
async def test_candidate_test_requires_inference_without_mutating_config(monkeypatch):
    from app.ai.configuration import test_candidate, AIConfigRequest, public_config
    before = public_config()
    wire(monkeypatch, lambda request: httpx.Response(401))
    result = await test_candidate(AIConfigRequest(base_url="http://localhost:1/v1", api_key="long-but-invalid",
                                                 model="fixture", routing_mode="single"))
    assert result["status"] == "error"
    assert result["routing"]["attempts"] == ["fixture"]
    assert public_config() == before


def test_candidate_does_not_forward_saved_key_to_changed_endpoint(monkeypatch):
    from app.ai.configuration import candidate_client, AIConfigRequest, llm_client
    monkeypatch.setattr(llm_client, "api_key", "synthetic-secret")
    assert candidate_client(AIConfigRequest(base_url="https://different.example.invalid/v1", model="fixture")).api_key == ""
    assert candidate_client(AIConfigRequest(api_key="")).api_key == "synthetic-secret"
    assert candidate_client(AIConfigRequest(clear_api_key=True)).api_key == ""


def test_runtime_update_is_shared_and_revision_conflicts_fail_before_mutation(monkeypatch):
    from app.ai import configuration
    from app.ai.gateway import AiGateway
    from app.core.config import settings
    client = LLMClient(base_url="http://localhost:1/v1", api_key="fixture", model="before", routing_mode="single")
    monkeypatch.setattr(configuration, "llm_client", client)
    monkeypatch.setattr(configuration, "_revision", 0)
    gateway = AiGateway()
    monkeypatch.setattr("app.ai.gateway.ai_gateway", gateway)
    for field in ["enabled", "provider", "base_url", "api_key", "model", "routing_mode", "temperature"]:
        monkeypatch.setattr(settings, "llm_" + field, getattr(settings, "llm_" + field))
    result = configuration.apply_runtime_config(configuration.AIConfigRequest(
        model="my-combo", routing_mode="router_combo", expected_revision=0))
    assert result["revision"] == 1
    assert settings.llm_model == client.model == gateway._provider.client.model == "my-combo"
    assert gateway._provider.client.effective_routing_mode == "router_combo"
    with pytest.raises(RuntimeError):
        configuration.apply_runtime_config(configuration.AIConfigRequest(model="stale", expected_revision=0))
    assert client.model == "my-combo"


@pytest.mark.asyncio
async def test_gateway_old_response_cannot_pollute_new_config_cache():
    from app.ai.gateway import AiGateway
    gateway = AiGateway()
    entered, release = asyncio.Event(), asyncio.Event()
    async def slow(*args):
        entered.set()
        await release.wait()
        return {"status": "success", "content": "old"}
    provider = type("Fixture", (), {})()
    provider.complete = slow
    gateway.set_provider(provider)
    task = asyncio.create_task(gateway.complete("fixture"))
    await entered.wait()
    gateway.set_provider(provider)
    release.set()
    await task
    assert gateway._cache == {}


@pytest.mark.asyncio
async def test_disabled_chat_cannot_be_reenabled_by_a_saved_key(monkeypatch):
    from fastapi import HTTPException
    from app.api.router import ai_chat_handler, AIChatRequest
    monkeypatch.setattr("app.core.config.settings.llm_enabled", False)
    monkeypatch.setattr("app.core.config.settings.llm_api_key", "saved-but-disabled")
    with pytest.raises(HTTPException) as exc:
        await ai_chat_handler(AIChatRequest(messages=[{"role": "user", "content": "fixture"}]))
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_html_and_mutable_scripts_revalidate_with_matching_asset_version():
    from app.main import app
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost") as client:
        page = await client.get("/")
        script = await client.get("/js/admin.js?v=2026.09.03-ai1")
        assert page.status_code == script.status_code == 200
        assert "must-revalidate" in page.headers["cache-control"]
        assert "must-revalidate" in script.headers["cache-control"]
        assert "js/admin.js?v=2026.09.03-ai1" in page.text
        assert "aiFormRevision" in script.text
