"""Test suite for Autonomous AI Execution Engine, Local-C Inference, and Nuclei Integration."""

import pytest
import asyncio
from app.ai.attack_planner import AttackPlanner, PlanStatus, StepStatus
from app.ai.hypothesis_engine import HypothesisEngine
from app.ai.local_c_inference_adapter import LocalCInferenceAdapter
from app.adapters.tools.nuclei_adapter import NucleiAdapter
from app.core.config import settings


@pytest.mark.asyncio
async def test_local_c_inference_adapter():
    """Verify offline local MoE inference adapter generates prioritized hypotheses."""
    adapter = LocalCInferenceAdapter()
    hypotheses = await adapter.generate_offline_hypotheses(
        target_domain="api.vuln-target.internal",
        assets=[{"hostname": "api.vuln-target.internal", "ip": "10.0.0.5"}],
        endpoints=[{"url": "https://api.vuln-target.internal/api/v1/user?id=1001", "path": "/api/v1/user"}],
        technologies=[{"name": "Laravel", "version": "10.0"}, {"name": "PHP", "version": "8.2"}],
        ports=[{"port": 80}, {"port": 443}, {"port": 8080}],
    )

    assert len(hypotheses) >= 2
    assert any("port" in h["statement"].lower() or "8080" in h["statement"] for h in hypotheses)
    assert any("php" in h["statement"].lower() or "env" in h["target_endpoint"] for h in hypotheses)
    assert any("id" in h["statement"].lower() or "idor" in h["statement"].lower() or "bola" in h["statement"].lower() for h in hypotheses)


@pytest.mark.asyncio
async def test_attack_planner_live_execution():
    """Verify AttackPlanner moves plans from DRAFT -> EXECUTING -> COMPLETED with step results."""
    planner = AttackPlanner()
    hyp_engine = HypothesisEngine()

    hyp = hyp_engine.create_hypothesis(
        statement="Target exposes unauthenticated administrative endpoint",
        target_endpoint="https://target.local/admin",
        initial_confidence=0.5,
        exploitability=0.8,
        impact=0.8,
        chain_potential=0.5,
        business_criticality=0.7,
        next_test="nuclei",
    )

    plan = planner.create_plan(
        title="Admin Endpoint Verification",
        target="https://target.local/admin",
        tool_sequence=["nuclei", "dalfox"],
        hypothesis_id=hyp.hypothesis_id,
    )

    assert plan.status == PlanStatus.DRAFT
    assert len(plan.steps) == 2
    assert plan.steps[0].status == StepStatus.PENDING

    # Execute plan asynchronously
    executed_plan = await planner.execute_plan_async(
        plan_id=plan.plan_id,
        scan_id="scan_test_123",
        hypothesis_engine=hyp_engine,
    )

    assert executed_plan is not None
    assert executed_plan.status == PlanStatus.COMPLETED
    assert executed_plan.progress == 1.0
    assert all(s.status == StepStatus.SUCCEEDED for s in executed_plan.steps)
    assert all(s.result is not None for s in executed_plan.steps)


@pytest.mark.asyncio
async def test_nuclei_adapter_execution():
    """Verify NucleiAdapter handles single and batch targets gracefully."""
    adapter = NucleiAdapter()
    res = await adapter.execute({
        "targets": ["https://target1.local", "https://target2.local"],
        "tags": "cve,misconfig",
    })

    assert res["status"] in ("success", "timeout")
    assert res["tool"] == "nuclei"
    assert "findings" in res


def test_concurrency_settings():
    """Verify concurrency defaults have been raised for high-throughput scans."""
    assert settings.max_concurrent_scans >= 4
    assert settings.max_pending_scans >= 50
    assert settings.nuclei_enabled is True
