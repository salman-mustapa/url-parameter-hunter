from __future__ import annotations

import uuid

import pytest

from app.ai.attack_planner import AttackPlanner
from app.ai.scan_loop import BASELINE_STAGES, scan_ai_controller
from app.core.engagement import EngagementRules
from app.core.profiles import is_deep_profile, supports_active_validation
from app.core.rate_limit import RateLimiter
from app.core.scope_engine import ScopeEngine
from app.core.tool_registry import ToolRegistry
from app.models.models import Scan
from app.orchestration.test_plan import test_plan_engine
from app.reporting.engine import ReportEngine
from app.scanners.base import ScanContext
from app.scanners.http import build_http_candidate_urls
from app.services.scan_manager import ScanManager
from app.core.db import AsyncSessionLocal


def _rules(**overrides):
    values = {
        "authorization_reference": "H1-PROGRAM-POLICY",
        "authorization_acknowledged": True,
        "scope_hosts": ["app.example.com"],
        "allowed_ports": [80, 443, 8443],
        "max_rps": 4,
        "allowed_techniques": ["safe_probe", "validation", "authentication_testing"],
        "prohibited_techniques": ["denial_of_service", "credential_stuffing"],
        "out_of_scope_findings": ["self_xss"],
    }
    values.update(overrides)
    return values


def test_profile_depth_is_independent_from_scope_breadth():
    assert is_deep_profile("deep_bug_hunt")
    assert is_deep_profile("pentest")
    assert is_deep_profile("adversary_simulation")
    assert supports_active_validation("deep_bug_hunt")
    assert [m.id for m in test_plan_engine.generate("app.example.com", "deep").modules] == [
        m.id for m in test_plan_engine.generate("app.example.com", "deep_bug_hunt").modules
    ]


def test_exact_operator_url_is_first_and_deep_aliases_get_extended_ports():
    scope = ScopeEngine("example.com", allowed_ports=[80, 443, 8443], recursive=True)
    ctx = ScanContext(
        "scan",
        scope,
        "deep_bug_hunt",
        {
            "target_host": "app.example.com",
            "target_url": "https://app.example.com:8443/api/orders?id=7",
        },
        RateLimiter(10),
    )
    candidates = build_http_candidate_urls(ctx, "app.example.com")
    assert candidates[0] == "https://app.example.com:8443/api/orders?id=7"
    assert "https://app.example.com:8443/" in candidates


def test_hackerone_policy_is_structured_and_prohibitions_win():
    rules = EngagementRules.model_validate(_rules())
    assert rules.action_allowed("authentication_testing")
    assert not rules.action_allowed("credential_stuffing")
    assert not rules.action_allowed("denial_of_service_validation")


def test_ai_plan_runtime_guard_blocks_scope_and_risk_escalation():
    planner = AttackPlanner(ToolRegistry())
    step = planner.create_plan(
        "SQLi check", "https://app.example.com/search?id=1", ["sqli_validator"]
    ).steps[0]
    scope = ScopeEngine("app.example.com", allowed_hosts=["app.example.com"], recursive=False)
    l2 = ScanContext(
        "scan", scope, "deep_bug_hunt",
        {"validation_level": "L2_SAFE_ACTIVE", "allowed_modules": ["*"], "allowed_actions": ["validation"]},
        RateLimiter(10),
    )
    assert "requires L3_CONTROLLED" in planner._runtime_policy_issue(step, "https://app.example.com/search?id=1", l2)
    l2.options["validation_level"] = "L3_CONTROLLED"
    assert planner._runtime_policy_issue(step, "https://app.example.com/search?id=1", l2) is None
    assert "outside" in planner._runtime_policy_issue(step, "https://other.example.com/", l2)


@pytest.mark.asyncio
async def test_scan_defaults_safe_and_controlled_mode_requires_rules(monkeypatch):
    manager = ScanManager()
    monkeypatch.setattr(manager, "_run", lambda *args: None)
    result = await manager.create_scan(
        target=f"safe-{uuid.uuid4().hex[:8]}.example.com",
        include_subdomains=False,
    )
    assert result["validation_level"] == "L2_SAFE_ACTIVE"
    assert result["options"]["authorized_high_risk"] is False
    assert result["options"]["rate_limit_rps"] <= 5

    with pytest.raises(ValueError, match="requires explicit engagement rules"):
        await manager.create_scan(
            target="app.example.com",
            validation_level="L3_CONTROLLED",
            include_subdomains=False,
        )

    controlled = await manager.create_scan(
        target="app.example.com",
        validation_level="L3_CONTROLLED",
        include_subdomains=False,
        engagement=_rules(),
    )
    async with AsyncSessionLocal() as db:
        stored = await db.get(Scan, controlled["scan_id"])
        assert stored.authorization_reference == "H1-PROGRAM-POLICY"
        assert stored.options["rate_limit_rps"] == 4
        assert stored.options["credential_audit"] is False


@pytest.mark.asyncio
async def test_ai_preflight_has_deterministic_coverage_when_cloud_is_disabled(monkeypatch):
    monkeypatch.setattr("app.core.config.settings.llm_enabled", False)
    scope = ScopeEngine("app.example.com", allowed_hosts=["app.example.com"], recursive=False)
    ctx = ScanContext(
        "scan", scope, "deep_bug_hunt",
        {"allowed_modules": ["*"], "allowed_actions": ["validation"]}, RateLimiter(10),
    )
    analysis = await scan_ai_controller.preflight(
        target="https://app.example.com/",
        profile="deep_bug_hunt",
        scope_mode="focused",
        validation_level="L3_CONTROLLED",
        engagement=_rules(),
        ctx=ctx,
    )
    assert analysis["baseline_stages"] == BASELINE_STAGES
    assert analysis["mode"] == "deterministic_fallback"


def test_hackerone_report_uses_submission_template_and_ai_review_section():
    report = ReportEngine.generate_bug_bounty_markdown(
        {"title": "Candidate", "severity": "HIGH"}, "app.example.com"
    )
    assert "## Steps To Reproduce" in report
    assert "## Impact" in report
    assert "NEEDS_REVIEW" in report
    assert "HTTP/1.1 200" not in report

    full = ReportEngine.generate_markdown(
        "scan", "app.example.com",
        {"report_context": {"ai_analysis": {"post_tools": {
            "executive_summary": "Evidence review complete.",
            "recommended_next_tests": ["nuclei"],
            "coverage_gaps": [],
            "recommended_techniques": ["baseline comparison"],
            "report_notes": ["Verify every claim."],
        }}}},
        [], [], [], [],
    )
    assert "AI Evidence Review & Recommended Next Actions" in full
    assert "Evidence review complete" in full
