import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from app.intelligence.llm_client import LLMClient, LLMResponseError, _completion_text


NOTICE = "Gemini 3.5 Flash is no longer available. Please switch to Gemini 3.7 Flash in the latest version of Antigravity."


@pytest.mark.parametrize("payload,code", [
    ({"choices": [{"message": {"content": NOTICE}, "finish_reason": "stop"}]}, "upstream_model_unavailable"),
    ({"choices": [{"message": {"reasoning": "not a final answer"}}]}, "missing_final_answer"),
    ({"choices": [{"message": {"content": "{}"}, "finish_reason": "length"}]}, "incomplete_completion"),
    ({"choices": [{"message": {"tool_calls": [{}]}, "finish_reason": "tool_calls"}]}, "incomplete_completion"),
    ({"error": {"message": "synthetic-secret"}, "choices": [{"message": {"content": "ok"}}]}, "provider_error"),
    ({"choices": {}}, "missing_completion"),
    ({"choices": [{"message": "invalid"}]}, "invalid_completion"),
])
def test_invalid_or_nonfinal_answers_are_not_success(payload, code):
    with pytest.raises(LLMResponseError) as exc:
        _completion_text(payload)
    assert exc.value.code == code
    assert "synthetic-secret" not in str(exc.value)


def test_final_text_blocks_are_supported_without_reasoning():
    assert _completion_text({"choices": [{"message": {"content": [
        {"type": "reasoning", "text": "private reasoning"},
        {"type": "text", "text": "final answer"},
    ]}}]}) == "final answer"


def wire(monkeypatch, handler):
    real_client = httpx.AsyncClient
    monkeypatch.setattr("app.intelligence.llm_client.httpx.AsyncClient",
                        lambda **kwargs: real_client(transport=httpx.MockTransport(handler), **kwargs))


@pytest.mark.asyncio
async def test_retired_model_notice_is_cascaded_and_audited(monkeypatch):
    requested = []
    def handler(request):
        requested.append(json.loads(request.content)["model"])
        content = NOTICE if len(requested) == 1 else "final answer"
        return httpx.Response(200, json={"model": "reported", "choices": [{"message": {"content": content}}]})
    wire(monkeypatch, handler)
    client = LLMClient(base_url="http://localhost:1/v1", api_key="fixture", model="combo", routing_mode="task_router")
    client.hermes_base_url = ""
    trace = {}
    assert await client.chat([{"role": "user", "content": "fixture"}], task="reasoning", timeout=2, _trace=trace) == "final answer"
    assert requested == ["security", "developer"]
    assert trace["failures"] == [{"model": "security", "error_code": "upstream_model_unavailable"}]
    assert trace["requested_model"] == "developer"


@pytest.mark.asyncio
async def test_single_combo_uses_configured_budget_without_hidden_twelve_second_cap(monkeypatch):
    budgets = []
    def handler(request):
        budgets.append(request.extensions["timeout"]["read"])
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})
    wire(monkeypatch, handler)
    client = LLMClient(base_url="http://localhost:1/v1", api_key="fixture", model="security", routing_mode="router_combo")
    assert await client.chat([{"role": "user", "content": "fixture"}], timeout=20) == "ok"
    assert 19 < budgets[0] <= 20


@pytest.mark.asyncio
async def test_readiness_requires_exact_marker(monkeypatch):
    monkeypatch.setattr(LLMClient, "chat", AsyncMock(return_value="Could not return PENTEST_AI_READY"))
    result = await LLMClient().test_connection()
    assert result["status"] == "error"


@pytest.mark.asyncio
@pytest.mark.parametrize("reply", ["upstream unavailable", "null", "[", '"not an object"'])
async def test_gateway_json_mode_rejects_non_json_answers(monkeypatch, reply):
    from app.ai.gateway import ConfiguredLLMProvider
    provider = ConfiguredLLMProvider({"enabled": True, "base_url": "http://localhost:1/v1", "model": "fixture"})
    monkeypatch.setattr(provider.client, "chat", AsyncMock(return_value=reply))
    result = await provider.complete("fixture", json_mode=True)
    assert result["status"] == "heuristic_fallback"
    assert result["fallback_reason"] == "provider_unavailable"


@pytest.mark.asyncio
@pytest.mark.parametrize("reply", ["{}", "upstream unavailable", '{"unexpected":true}'])
async def test_invalid_scan_analysis_is_explicit_fallback(monkeypatch, reply):
    from app.ai import scan_loop
    monkeypatch.setattr(scan_loop, "llm_client", SimpleNamespace(is_configured=True, chat=AsyncMock(return_value=reply)))
    pre = await scan_loop.scan_ai_controller.preflight(target="app.example.invalid", profile="deep_bug_hunt",
        scope_mode="focused", validation_level="L2_SAFE_ACTIVE", engagement={}, ctx=None)
    post = await scan_loop.scan_ai_controller.post_tools(target="app.example.invalid", profile="deep_bug_hunt",
        engagement={}, snapshot={"findings": [], "coverage_failures": ["tool missing"]}, ctx=None)
    for result in (pre, post):
        assert result["status"] == "fallback"
        assert result["mode"] == "deterministic_fallback"
    assert pre["baseline_stages"] == scan_loop.BASELINE_STAGES
    assert post["coverage_gaps"] == ["tool missing"]


@pytest.mark.asyncio
async def test_successful_ai_review_preserves_policy_and_evidence_warnings(monkeypatch):
    from app.ai import scan_loop
    reply = {"objective": "Review supplied evidence", "prioritized_areas": [], "recommended_tools": [],
             "policy_summary": [], "cautions": ["AI caution"], "executive_summary": "Candidate needs review.",
             "coverage_gaps": [], "recommended_next_tests": [], "recommended_techniques": [],
             "report_notes": ["AI note"]}
    monkeypatch.setattr(scan_loop, "llm_client", SimpleNamespace(is_configured=True, chat=AsyncMock(return_value=json.dumps(reply))))
    pre = await scan_loop.scan_ai_controller.preflight(target="app.example.invalid", profile="deep_bug_hunt",
        scope_mode="full", validation_level="L2_SAFE_ACTIVE", engagement={"prohibited_techniques": ["No DoS"]}, ctx=None)
    post = await scan_loop.scan_ai_controller.post_tools(target="app.example.invalid", profile="deep_bug_hunt",
        engagement={}, snapshot={"findings": [], "coverage_failures": ["tool missing"]}, ctx=None)
    assert pre["cautions"] == ["No DoS", "AI caution"]
    assert post["coverage_gaps"] == ["tool missing"]
    assert "Do not describe unverified candidates as confirmed vulnerabilities." in post["report_notes"]
    assert pre["mode"] == post["mode"] == "cloud_ai_with_deterministic_guard"


@pytest.mark.asyncio
async def test_provider_recovery_is_not_hidden_by_cached_fallback():
    from app.ai.gateway import AiGateway
    provider = SimpleNamespace(complete=AsyncMock(side_effect=[
        {"status": "heuristic_fallback", "content": "offline"},
        {"status": "success", "content": "recovered"},
    ]))
    gateway = AiGateway()
    gateway.set_provider(provider)
    assert (await gateway.complete("fixture"))["status"] == "heuristic_fallback"
    assert (await gateway.complete("fixture"))["content"] == "recovered"
    assert (await gateway.complete("fixture"))["content"] == "recovered"
    assert provider.complete.await_count == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("prompt", ["fixture", "SQL syntax", "CREATE TABLE", "JWT_SECRET=", "404 not found"])
async def test_offline_keyword_triage_never_confirms_or_authorizes(prompt):
    from app.ai.gateway import ZeroResourceHeuristicProvider
    result = await ZeroResourceHeuristicProvider().complete(prompt)
    decision = result["structured"]
    assert not decision["decision"].startswith("CONFIRMED")
    assert not decision["is_actionable"]
    assert decision["requires_evidence_validation"]
