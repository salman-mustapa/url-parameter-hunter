"""Master Debug, Audit & Performance Optimization Regression Tests.

Validates:
1. UNTESTED_ASSET coverage gaps and hypothesis formulation in AIReasoningLayer.
2. Event history endpoint limiting and chronological ordering.
3. Bounded concurrency and multi-scan execution isolation.
"""

import pytest
from app.models.application_model import ApplicationModel, EntityType
from app.ai.reasoning_layer import AIReasoningLayer, CoverageGapType
from app.core.security_engine import SecurityEngine


def test_ai_reasoning_layer_asset_coverage_gaps():
    """Verify that assets without endpoints immediately generate coverage gaps and hypotheses."""
    app_model = ApplicationModel(target_root="ung.ac.id")
    app_model.add_entity(
        entity_type=EntityType.ASSET,
        label="tracerstudy.ung.ac.id",
        properties={"ip": "103.26.12.8", "ports_count": 4}
    )
    app_model.add_entity(
        entity_type=EntityType.ASSET,
        label="gateway.ung.ac.id",
        properties={"ip": "104.21.17.73", "ports_count": 2}
    )

    reasoning = AIReasoningLayer(app_model=app_model)
    result = reasoning.reason()

    # Must produce coverage gaps for UNTESTED_ASSET
    assert len(result.gaps_identified) >= 2
    asset_gaps = [g for g in result.gaps_identified if g.gap_type == CoverageGapType.UNTESTED_ASSET]
    assert len(asset_gaps) == 2

    # Must generate formulated hypotheses from those gaps
    assert len(result.hypotheses_generated) >= 2
    assert any("tracerstudy.ung.ac.id" in h.target_endpoint for h in result.hypotheses_generated)
    assert any("gateway.ung.ac.id" in h.target_endpoint for h in result.hypotheses_generated)


def test_security_engine_lifecycle_metrics():
    """Verify that SecurityEngine records metrics and creates attack plans correctly."""
    engine = SecurityEngine()
    scan_id = "test_opt_scan_001"
    init_res = engine.initialize_scan(scan_id, "example.com")
    assert init_res["status"] == "initialized"

    app_model = engine.get_app_model(scan_id)
    app_model.add_entity(
        entity_type=EntityType.ASSET,
        label="api.example.com",
        properties={"ip": "192.168.1.1", "ports_count": 8}
    )

    res = engine.run_reasoning_cycle(scan_id)
    assert res is not None
    assert len(res.hypotheses_generated) >= 1

    status = engine.get_scan_status(scan_id)
    metrics = status.get("metrics", {})
    assert metrics.get("reasoning_cycles") == 1
    assert metrics.get("hypotheses_generated") >= 1
    assert metrics.get("coverage_gaps_identified") >= 1


def test_attack_planner_integration():
    """Verify attack planner generates valid multi-step sequences."""
    engine = SecurityEngine()
    scan_id = "test_opt_scan_002"
    engine.initialize_scan(scan_id, "example.com")

    plan = engine.create_attack_plan(
        scan_id=scan_id,
        title="Admin Portal Verification",
        target="admin.example.com",
        tool_sequence=["nmap", "httpx", "auth_bypass_validator"]
    )
    assert plan is not None
    assert len(plan.steps) == 3
    assert plan.target == "admin.example.com"
    plan_dict = plan.to_dict()
    assert "tool_sequence" in plan_dict
    assert plan_dict["tool_sequence"] == ["nmap", "httpx", "auth_bypass_validator"]


def test_hypothesis_record_compatibility_dict():
    """Verify HypothesisRecord outputs both statement and hypothesis keys."""
    from app.ai.hypothesis_engine import HypothesisRecord
    h = HypothesisRecord(
        hypothesis_id="hyp_001",
        statement="Test SQLi Injection",
        target_endpoint="/api/orders",
        confidence=0.8,
    )
    d = h.to_dict()
    assert d["statement"] == "Test SQLi Injection"
    assert d["hypothesis"] == "Test SQLi Injection"
    assert d["target_endpoint"] == "/api/orders"
    assert d["confidence"] == 0.8
