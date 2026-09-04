import asyncio
import time
import uuid
from datetime import datetime, timezone, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.ai.attack_planner import AttackPlanner
from app.core.db import AsyncSessionLocal
from app.core.engagement import EngagementRules
from app.core.events import EventBus
from app.core.tool_registry import ToolRegistry
from app.intelligence.llm_client import LLMClient
from app.models.models import Scan, ScanEvent
from app.services.scan_manager import ScanManager


@pytest.mark.asyncio
async def test_model_deadline_includes_waiting_for_concurrency_slot():
    client = LLMClient(base_url="http://localhost:1/v1", api_key="synthetic", model="fixture")
    client._semaphore = asyncio.Semaphore(0)
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        await client.chat([{"role": "user", "content": "fixture"}], timeout=.05)
    assert time.monotonic() - started < .5


@pytest.mark.asyncio
async def test_timeout_preserves_scan_and_marks_coverage_incomplete(monkeypatch):
    manager = ScanManager()
    scan_id = str(uuid.uuid4())
    async with AsyncSessionLocal() as db:
        db.add(Scan(id=scan_id, root_domain="example.invalid", status="running"))
        await db.commit()
    monkeypatch.setattr(manager, "_pipeline", AsyncMock(side_effect=TimeoutError))
    await manager._execute_with_timeout(scan_id, "example.invalid", "deep", {})
    async with AsyncSessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        assert scan.status == "degraded"
        assert not scan.progress["coverage_complete"]
        assert scan.progress["coverage_failures"][0]["phase"] == "runtime"


@pytest.mark.asyncio
async def test_local_live_events_do_not_depend_on_redis_listener():
    bus = EventBus()
    handler = AsyncMock()
    bus.subscribe("*", handler)
    bus._redis = AsyncMock()
    await bus.publish({"scan_id": "one", "type": "port.open"})
    assert handler.await_count == 1
    bus._redis.publish.side_effect = ConnectionError("fixture")
    await bus.publish({"scan_id": "two", "type": "port.open"})
    assert handler.await_count == 2


def test_empty_technique_list_does_not_grant_credential_or_extraction_permissions():
    rules = EngagementRules(authorization_reference="fixture", authorization_acknowledged=True)
    assert rules.action_allowed("validation")
    assert not rules.action_allowed("credential_audit")
    assert not rules.action_allowed("artifact_analysis")
    assert not rules.action_allowed("auth")


def test_provider_key_is_not_forwarded_to_a_different_endpoint(monkeypatch):
    monkeypatch.setattr("app.core.config.settings.llm_api_key", "synthetic-provider-secret")
    assert LLMClient(base_url="https://different.example.invalid/v1").api_key == ""
    assert LLMClient(api_key="").api_key == ""


@pytest.mark.asyncio
async def test_missing_tool_or_executor_is_not_a_clean_result():
    planner = AttackPlanner(ToolRegistry())
    plan = planner.create_plan("Fixture", "https://example.invalid/", ["sqli_validator"])
    result = await planner._dispatch_step_execution(plan.steps[0], plan.target, "fixture")
    assert result["status"] == "blocked"
    plan.steps[0].tool_name = "unbound_tool"
    result = await planner._dispatch_step_execution(plan.steps[0], plan.target, "fixture")
    assert result["status"] == "blocked"


@pytest.mark.asyncio
async def test_missing_nuclei_is_unavailable_not_clean(monkeypatch):
    from app.adapters.tools.nuclei_adapter import NucleiAdapter
    adapter = NucleiAdapter()
    adapter._binary_path = None
    result = await adapter.execute({"target": "https://example.invalid/"})
    assert result["status"] == "unavailable"


@pytest.mark.asyncio
async def test_policy_review_is_advisory_and_does_not_invent_offline_scope(monkeypatch):
    from app.api.policy_review import PolicyReviewRequest, review_program_policy
    monkeypatch.setattr("app.core.config.settings.llm_enabled", False)
    result = await review_program_policy(PolicyReviewRequest(policy_text="Only app.example.invalid is in scope."))
    assert result["requires_operator_review"] is True
    assert result["status"] == "unavailable"
    assert result["in_scope"] == []


@pytest.mark.asyncio
async def test_sse_replay_preserves_event_ids_and_is_not_truncated_by_live_queue(monkeypatch):
    from app.api.router import scan_events
    from app.services.results import ResultService
    scan_id = str(uuid.uuid4())
    instant = datetime.now(timezone.utc)
    ids = [f"evt_{uuid.uuid4().hex}" for _ in range(4)]
    async with AsyncSessionLocal() as db:
        db.add(Scan(id=scan_id, root_domain="example.invalid"))
        await db.commit()
    await ResultService()._flush_batch([
        {"event_id": eid, "created_at": instant + timedelta(microseconds=i),
         "scan_id": scan_id, "event_type": "fixture", "data": {}}
        for i, eid in enumerate(ids)
    ])
    async with AsyncSessionLocal() as db:
        event = await db.get(ScanEvent, ids[0])
        assert event.created_at.replace(tzinfo=timezone.utc) == instant
    monkeypatch.setattr("app.core.config.settings.sse_client_queue_size", 1)
    request = SimpleNamespace(headers={"last-event-id": ids[0]}, is_disconnected=AsyncMock(return_value=True))
    response = await scan_events(scan_id, request)
    frames = [frame async for frame in response.body_iterator]
    assert len(frames) == 3
    for frame, eid in zip(frames, ids[1:]):
        assert f"id: {eid}\n" in frame


@pytest.mark.asyncio
async def test_terminal_scan_cannot_be_resumed_without_a_runner():
    with pytest.raises(ValueError, match="No live runner"):
        await ScanManager().resume("completed-fixture")


def test_full_and_focused_keep_the_same_probes_for_the_explicit_target():
    from app.scanners.base import ScanContext
    from app.scanners.http import build_http_candidate_urls
    from app.core.scope_engine import ScopeEngine
    from app.core.rate_limit import RateLimiter
    probes = []
    for recursive in (True, False):
        scope = ScopeEngine("app.example.com", allowed_hosts=["app.example.com"], recursive=recursive)
        ctx = ScanContext("fixture", scope, "deep_bug_hunt", {
            "include_subdomains": recursive, "target_url": "https://app.example.com:8443/route?Case=Exact",
        }, RateLimiter(5))
        probes.append(build_http_candidate_urls(ctx, "app.example.com"))
    assert probes[0] == probes[1]
    assert probes[0][0].endswith("/route?Case=Exact")
