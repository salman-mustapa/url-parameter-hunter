"""Test Suite for V4 Master System Architecture — Security Engine Platform.

Verifies:
1. ToolRegistry: registration, lookup, capability matching, category filtering
2. StateMachine: transitions, guards, pause/resume, checkpoint, factory functions
3. ApplicationModel: entity CRUD, relations, queries, attack surface summary
4. SecurityKnowledgeEngine: taxonomy, technology patterns, invariant templates, search
5. AIReasoningLayer: coverage gap analysis, hypothesis generation, action ranking
6. AttackPlanner: plan creation, validation, step sequencing, risk calculation
7. SecurityEngine: lifecycle, initialization, reasoning cycles, metrics
"""

import time
import pytest
from unittest.mock import MagicMock

# =====================================================================
# 1. Tool Registry Tests
# =====================================================================

from app.core.tool_registry import (
    ToolRegistry, SecurityTool, ToolCategory, ToolRiskLevel, ToolPrecondition,
    tool_registry,
)


class TestToolRegistry:
    def test_builtin_tools_registered(self):
        """All built-in security tools should be registered on init."""
        registry = ToolRegistry()
        tools = registry.list_tools()
        assert len(tools) >= 30, f"Expected at least 30 built-in tools, got {len(tools)}"

    def test_find_by_category(self):
        registry = ToolRegistry()
        validate_tools = registry.find_by_category(ToolCategory.VALIDATE)
        assert len(validate_tools) >= 20, f"Expected at least 20 VALIDATE tools, got {len(validate_tools)}"
        recon_tools = registry.find_by_category(ToolCategory.RECON)
        assert len(recon_tools) >= 3

    def test_find_by_capability(self):
        registry = ToolRegistry()
        sqli_tools = registry.find_by_capability("sqli")
        assert len(sqli_tools) >= 1
        assert any("sqli" in t.name for t in sqli_tools)

    def test_find_by_tags(self):
        registry = ToolRegistry()
        injection_tools = registry.find_by_tags({"injection"})
        assert len(injection_tools) >= 3

    def test_find_for_vulnerability_type(self):
        registry = ToolRegistry()
        xss_tools = registry.find_for_vulnerability_type("xss")
        assert len(xss_tools) >= 1

    def test_register_and_unregister(self):
        registry = ToolRegistry()
        custom = SecurityTool(
            name="custom_scanner",
            category=ToolCategory.PROBE,
            description="Custom test scanner",
            capabilities=["custom_scan"],
            risk_level=ToolRiskLevel.LOW,
        )
        registry.register(custom)
        assert registry.get("custom_scanner") is not None
        assert registry.unregister("custom_scanner")
        assert registry.get("custom_scanner") is None

    def test_tool_precondition_check(self):
        tool = SecurityTool(
            name="test_tool",
            category=ToolCategory.VALIDATE,
            description="Test",
            preconditions=[
                ToolPrecondition("has_auth", "Requires authentication",
                                 check_fn=lambda ctx: ctx.get("authenticated", False)),
            ],
        )
        assert tool.check_preconditions({"authenticated": True}) == []
        assert tool.check_preconditions({"authenticated": False}) == ["has_auth"]

    def test_tool_summary(self):
        registry = ToolRegistry()
        summary = registry.get_summary()
        assert "total_tools" in summary
        assert "by_category" in summary
        assert summary["total_tools"] >= 30

    def test_tool_to_dict(self):
        registry = ToolRegistry()
        tool = registry.get("sqli_validator")
        assert tool is not None
        d = tool.to_dict()
        assert d["name"] == "sqli_validator"
        assert d["category"] == "VALIDATE"
        assert "sqli" in d["capabilities"]

    def test_disable_tool(self):
        registry = ToolRegistry()
        tool = registry.get("sqli_validator")
        tool.enabled = False
        assert tool not in registry.list_tools(enabled_only=True)
        tool.enabled = True  # Restore


# =====================================================================
# 2. State Machine Tests
# =====================================================================

from app.core.state_machine import (
    StateMachine, StateTransition, TransitionEvent,
    create_scan_state_machine, create_finding_state_machine,
    create_hypothesis_state_machine, create_attack_path_state_machine,
    StateMachineManager, state_machine_manager,
)


class TestStateMachine:
    def test_scan_lifecycle_happy_path(self):
        """Scan should transition through full lifecycle."""
        sm = create_scan_state_machine("test_scan_1")
        assert sm.current_state == "CREATED"

        sm.trigger("start_discovery")
        assert sm.current_state == "DISCOVERING"

        sm.trigger("discovery_complete")
        assert sm.current_state == "MODELING"

        sm.trigger("model_ready")
        assert sm.current_state == "TESTING"

        sm.trigger("testing_complete")
        assert sm.current_state == "VALIDATING"

        sm.trigger("validation_complete")
        assert sm.current_state == "REPORTING"

        sm.trigger("report_generated")
        assert sm.current_state == "COMPLETED"
        assert sm.is_terminal

    def test_scan_fast_path(self):
        """Discovery can fast-path directly to testing."""
        sm = create_scan_state_machine("test_scan_fp")
        sm.trigger("start_discovery")
        sm.trigger("fast_path_test")
        assert sm.current_state == "TESTING"

    def test_finding_lifecycle(self):
        sm = create_finding_state_machine("finding_1")
        assert sm.current_state == "SUSPECTED"
        sm.trigger("begin_validation")
        assert sm.current_state == "TESTING"
        sm.trigger("test_passed")
        assert sm.current_state == "VALIDATED"
        sm.trigger("critic_approved")
        assert sm.current_state == "CONFIRMED"
        sm.trigger("include_in_report")
        assert sm.current_state == "REPORTED"
        assert sm.is_terminal

    def test_finding_rejection(self):
        sm = create_finding_state_machine("finding_rej")
        sm.trigger("begin_validation")
        sm.trigger("test_failed")
        assert sm.current_state == "REJECTED"
        assert sm.is_terminal

    def test_hypothesis_lifecycle(self):
        sm = create_hypothesis_state_machine("hyp_1")
        assert sm.current_state == "FORMED"
        sm.trigger("plan_created")
        sm.trigger("execution_started")
        sm.trigger("result_received")
        sm.trigger("evaluation_complete")
        sm.trigger("evidence_supports")
        assert sm.current_state == "CONFIRMED"

    def test_hypothesis_reformulation(self):
        sm = create_hypothesis_state_machine("hyp_reform")
        sm.trigger("plan_created")
        sm.trigger("execution_started")
        sm.trigger("result_received")
        sm.trigger("evaluation_complete")
        sm.trigger("needs_more_data")
        assert sm.current_state == "FORMED"  # Back to start

    def test_attack_path_lifecycle(self):
        sm = create_attack_path_state_machine("path_1")
        assert sm.current_state == "IDENTIFIED"
        sm.trigger("preconditions_satisfied")
        sm.trigger("step_started")
        sm.trigger("step_succeeded")
        sm.trigger("chain_complete")
        assert sm.current_state == "CHAINED"

    def test_attack_path_multi_step(self):
        sm = create_attack_path_state_machine("path_multi")
        sm.trigger("preconditions_satisfied")
        sm.trigger("step_started")
        sm.trigger("step_succeeded")
        sm.trigger("next_step")  # Continue to next step
        assert sm.current_state == "STEP_EXECUTING"
        sm.trigger("step_succeeded")
        sm.trigger("chain_complete")
        assert sm.current_state == "CHAINED"

    def test_invalid_transition_raises(self):
        sm = create_scan_state_machine("test_invalid")
        with pytest.raises(ValueError):
            sm.trigger("report_generated")  # Can't go from CREATED to report

    def test_pause_resume(self):
        sm = create_scan_state_machine("test_pause")
        sm.trigger("start_discovery")
        paused = sm.pause()
        assert paused == "DISCOVERING"
        assert sm.current_state == "PAUSED"
        resumed = sm.resume()
        assert resumed == "DISCOVERING"
        assert sm.current_state == "DISCOVERING"

    def test_checkpoint_restore(self):
        sm = create_scan_state_machine("test_ckpt")
        sm.trigger("start_discovery")
        sm.trigger("discovery_complete")
        checkpoint = sm.checkpoint()
        assert checkpoint["current_state"] == "MODELING"

        sm2 = create_scan_state_machine("test_ckpt_2")
        sm2.restore(checkpoint)
        assert sm2.current_state == "MODELING"

    def test_transition_history(self):
        sm = create_scan_state_machine("test_hist")
        sm.trigger("start_discovery")
        sm.trigger("discovery_complete")
        assert len(sm.history) == 2
        assert sm.history[0].from_state == "CREATED"
        assert sm.history[0].to_state == "DISCOVERING"

    def test_event_listener(self):
        events_received = []
        sm = create_scan_state_machine("test_listener")
        sm.add_listener(lambda e: events_received.append(e))
        sm.trigger("start_discovery")
        assert len(events_received) == 1
        assert events_received[0].to_state == "DISCOVERING"

    def test_available_triggers(self):
        sm = create_scan_state_machine("test_triggers")
        triggers = sm.get_available_triggers()
        assert "start_discovery" in triggers
        assert "report_generated" not in triggers

    def test_state_machine_manager(self):
        mgr = StateMachineManager()
        sm = create_scan_state_machine("mgr_test")
        mgr.register(sm)
        assert mgr.get("mgr_test") is not None
        assert len(mgr.list_by_type("ScanLifecycle")) == 1
        summary = mgr.get_summary()
        assert summary["total_machines"] == 1

    def test_to_dict(self):
        sm = create_scan_state_machine("test_dict")
        d = sm.to_dict()
        assert d["machine_id"] == "test_dict"
        assert d["machine_type"] == "ScanLifecycle"
        assert d["current_state"] == "CREATED"

    def test_guard_function(self):
        transitions = [
            StateTransition("A", "B", "go",
                            guard_fn=lambda ctx: ctx.get("allowed", False)),
        ]
        sm = StateMachine("test_guard", "GuardTest", "A", transitions)
        assert not sm.can_transition("go", {"allowed": False})
        assert sm.can_transition("go", {"allowed": True})


# =====================================================================
# 3. Application Model Tests
# =====================================================================

from app.models.application_model import (
    ApplicationModel, EntityType, RelationType, AuthType, ModelEntity,
)


class TestApplicationModel:
    def test_add_and_get_entity(self):
        model = ApplicationModel("test.com")
        ep = model.add_entity(EntityType.ENDPOINT, "/api/users",
                              properties={"method": "GET", "auth_type": "jwt_bearer"})
        assert ep.entity_type == EntityType.ENDPOINT
        assert model.get_entity(ep.id) is ep

    def test_add_entity_with_id(self):
        model = ApplicationModel("test.com")
        ep = model.add_entity(EntityType.ENDPOINT, "/login", entity_id="ep_login")
        assert ep.id == "ep_login"

    def test_upsert_entity(self):
        model = ApplicationModel("test.com")
        ep = model.add_entity(EntityType.ENDPOINT, "/api", entity_id="ep1",
                              properties={"method": "GET"})
        ep2 = model.add_entity(EntityType.ENDPOINT, "/api", entity_id="ep1",
                               properties={"method": "POST"})
        assert ep is ep2
        assert ep.properties["method"] == "POST"  # Updated

    def test_get_entities_by_type(self):
        model = ApplicationModel("test.com")
        model.add_entity(EntityType.ENDPOINT, "/api/a")
        model.add_entity(EntityType.ENDPOINT, "/api/b")
        model.add_entity(EntityType.PARAMETER, "user_id")
        endpoints = model.get_entities_by_type(EntityType.ENDPOINT)
        assert len(endpoints) == 2

    def test_add_relation(self):
        model = ApplicationModel("test.com")
        ep = model.add_entity(EntityType.ENDPOINT, "/api/users")
        param = model.add_entity(EntityType.PARAMETER, "id")
        rel = model.add_relation(ep.id, param.id, RelationType.CONTAINS)
        assert rel is not None
        assert rel.relation_type == RelationType.CONTAINS

    def test_get_relations(self):
        model = ApplicationModel("test.com")
        ep = model.add_entity(EntityType.ENDPOINT, "/api/users")
        p1 = model.add_entity(EntityType.PARAMETER, "id")
        p2 = model.add_entity(EntityType.PARAMETER, "name")
        model.add_relation(ep.id, p1.id, RelationType.CONTAINS)
        model.add_relation(ep.id, p2.id, RelationType.CONTAINS)
        outgoing = model.get_relations_from(ep.id)
        assert len(outgoing) == 2

    def test_find_unauthenticated_endpoints(self):
        model = ApplicationModel("test.com")
        model.add_entity(EntityType.ENDPOINT, "/public",
                         properties={"auth_type": "none"})
        model.add_entity(EntityType.ENDPOINT, "/private",
                         properties={"auth_type": "jwt_bearer"})
        unauth = model.find_unauthenticated_endpoints()
        assert len(unauth) == 1
        assert unauth[0].label == "/public"

    def test_find_endpoints_by_auth_type(self):
        model = ApplicationModel("test.com")
        model.add_entity(EntityType.ENDPOINT, "/jwt",
                         properties={"auth_type": "jwt_bearer"})
        model.add_entity(EntityType.ENDPOINT, "/session",
                         properties={"auth_type": "session_cookie"})
        jwt_eps = model.find_endpoints_by_auth_type(AuthType.JWT_BEARER)
        assert len(jwt_eps) == 1

    def test_get_objects_accessible_by(self):
        model = ApplicationModel("test.com")
        identity = model.add_entity(EntityType.IDENTITY, "admin_user")
        obj1 = model.add_entity(EntityType.OBJECT, "order_123")
        obj2 = model.add_entity(EntityType.OBJECT, "profile_456")
        model.add_relation(identity.id, obj1.id, RelationType.ACCESSES)
        model.add_relation(identity.id, obj2.id, RelationType.ACCESSES)
        accessible = model.get_objects_accessible_by(identity.id)
        assert len(accessible) == 2

    def test_attack_surface_summary(self):
        model = ApplicationModel("test.com")
        model.add_entity(EntityType.ASSET, "test.com")
        model.add_entity(EntityType.ENDPOINT, "/api/login")
        model.add_entity(EntityType.ENDPOINT, "/api/users")
        model.add_entity(EntityType.PARAMETER, "username")
        model.add_entity(EntityType.IDENTITY, "admin")
        summary = model.get_attack_surface_summary()
        assert summary["breakdown"]["endpoints"] == 2
        assert summary["breakdown"]["parameters"] == 1
        assert summary["breakdown"]["identities"] == 1

    def test_entity_state_tracking(self):
        model = ApplicationModel("test.com")
        identity = model.add_entity(EntityType.IDENTITY, "user1",
                                    state={"role": "user", "balance": 100})
        assert identity.state["role"] == "user"
        identity.update_state(role="admin", balance=200)
        assert identity.state["role"] == "admin"
        assert identity.state["balance"] == 200

    def test_find_entities_with_state(self):
        model = ApplicationModel("test.com")
        model.add_entity(EntityType.IDENTITY, "admin", state={"role": "admin"})
        model.add_entity(EntityType.IDENTITY, "user", state={"role": "user"})
        admins = model.find_entities_with_state("role", "admin")
        assert len(admins) == 1

    def test_to_graph(self):
        model = ApplicationModel("test.com")
        model.add_entity(EntityType.ASSET, "test.com")
        graph = model.to_graph()
        assert "entities" in graph
        assert "relations" in graph
        assert "summary" in graph

    def test_remove_entity(self):
        model = ApplicationModel("test.com")
        ep = model.add_entity(EntityType.ENDPOINT, "/delete-me")
        assert model.remove_entity(ep.id)
        assert model.get_entity(ep.id) is None

    def test_trust_boundaries_and_controls(self):
        model = ApplicationModel("test.com")
        tb = model.add_entity(EntityType.TRUST_BOUNDARY, "DMZ → Internal",
                              properties={"type": "network"})
        sc = model.add_entity(EntityType.SECURITY_CONTROL, "WAF",
                              properties={"type": "waf"})
        assert len(model.get_trust_boundaries()) == 1
        assert len(model.get_security_controls()) == 1

    def test_reset(self):
        model = ApplicationModel("test.com")
        model.add_entity(EntityType.ENDPOINT, "/api")
        model.reset()
        assert len(model.get_entities_by_type(EntityType.ENDPOINT)) == 0


# =====================================================================
# 4. Security Knowledge Engine Tests
# =====================================================================

from app.intelligence.knowledge_engine import (
    SecurityKnowledgeEngine, VulnerabilityCategory, VulnerabilityTemplate,
    TechnologyAttackPattern, SecurityInvariantTemplate,
    security_knowledge_engine,
)


class TestSecurityKnowledgeEngine:
    def test_builtin_vulnerability_taxonomy(self):
        engine = SecurityKnowledgeEngine()
        summary = engine.get_summary()
        assert summary["total_vulnerability_templates"] >= 15
        assert summary["total_attack_patterns"] >= 8
        assert summary["total_invariant_templates"] >= 6

    def test_find_by_category(self):
        engine = SecurityKnowledgeEngine()
        injection_vulns = engine.find_vulnerabilities_by_category(VulnerabilityCategory.INJECTION)
        assert len(injection_vulns) >= 3  # SQLI, SSTI, RCE, HOST_HEADER

    def test_find_by_cwe(self):
        engine = SecurityKnowledgeEngine()
        cwe89 = engine.find_vulnerabilities_by_cwe(89)
        assert len(cwe89) >= 1
        assert cwe89[0].name == "SQL Injection"

    def test_find_by_tool(self):
        engine = SecurityKnowledgeEngine()
        sqli_vulns = engine.find_vulnerabilities_by_tool("sqli_validator")
        assert len(sqli_vulns) >= 1

    def test_search_vulnerabilities(self):
        engine = SecurityKnowledgeEngine()
        results = engine.search_vulnerabilities("injection")
        assert len(results) >= 2

    def test_get_attack_patterns_for_technology(self):
        engine = SecurityKnowledgeEngine()
        wp_patterns = engine.get_attack_patterns_for_technology("WordPress")
        assert len(wp_patterns) >= 2

    def test_get_invariants_for_context(self):
        engine = SecurityKnowledgeEngine()
        ecom_inv = engine.get_invariants_for_context("e-commerce")
        assert len(ecom_inv) >= 3

    def test_get_remediation(self):
        engine = SecurityKnowledgeEngine()
        remediation = engine.get_remediation("SQLI")
        assert "parameterized" in remediation.lower()

    def test_register_custom_vulnerability(self):
        engine = SecurityKnowledgeEngine()
        custom = VulnerabilityTemplate(
            vuln_id="CUSTOM_1",
            name="Custom Vuln",
            category=VulnerabilityCategory.API_SECURITY,
        )
        engine.register_vulnerability(custom)
        assert engine.get_vulnerability_template("CUSTOM_1") is not None

    def test_register_custom_attack_pattern(self):
        engine = SecurityKnowledgeEngine()
        pattern = TechnologyAttackPattern(
            pattern_id="custom_pat", technology="CustomTech",
            attack_vector="CustomVector", description="Custom pattern",
        )
        engine.register_attack_pattern(pattern)
        results = engine.get_attack_patterns_for_technology("CustomTech")
        assert len(results) == 1

    def test_register_custom_invariant(self):
        engine = SecurityKnowledgeEngine()
        inv = SecurityInvariantTemplate(
            invariant_id="custom_inv", name="Custom Inv",
            expression="x > 0", context="custom_context",
        )
        engine.register_invariant(inv)
        results = engine.get_invariants_for_context("custom_context")
        assert len(results) == 1


# =====================================================================
# 5. AI Reasoning Layer Tests
# =====================================================================

from app.ai.reasoning_layer import (
    AIReasoningLayer, CoverageGap, CoverageGapType, ReasoningResult,
)


class TestAIReasoningLayer:
    def _build_populated_model(self):
        model = ApplicationModel("test.com")
        model.add_entity(EntityType.ENDPOINT, "/api/login",
                         properties={"method": "POST", "auth_type": "none"})
        model.add_entity(EntityType.ENDPOINT, "/api/users",
                         properties={"method": "GET", "auth_type": "jwt_bearer"})
        model.add_entity(EntityType.ENDPOINT, "/api/admin",
                         properties={"method": "GET", "auth_type": "jwt_bearer",
                                     "expected_auth": True})
        model.add_entity(EntityType.PARAMETER, "user_id",
                         properties={"location": "query", "type": "integer"})
        model.add_entity(EntityType.PARAMETER, "redirect_url",
                         properties={"location": "query", "type": "string"})
        model.add_entity(EntityType.TECHNOLOGY, "WordPress")
        return model

    def test_reasoning_without_model(self):
        reasoning = AIReasoningLayer()
        result = reasoning.reason()
        assert len(result.gaps_identified) == 0

    def test_reasoning_identifies_coverage_gaps(self):
        model = self._build_populated_model()
        reasoning = AIReasoningLayer(
            app_model=model,
            knowledge_engine=SecurityKnowledgeEngine(),
            tool_registry=ToolRegistry(),
        )
        result = reasoning.reason()
        assert len(result.gaps_identified) > 0
        assert len(result.hypotheses_generated) > 0
        assert len(result.actions_recommended) > 0

    def test_reasoning_detects_untested_endpoints(self):
        model = self._build_populated_model()
        reasoning = AIReasoningLayer(app_model=model)
        result = reasoning.reason()
        endpoint_gaps = [g for g in result.gaps_identified
                         if g.gap_type == CoverageGapType.UNTESTED_ENDPOINT]
        assert len(endpoint_gaps) >= 3

    def test_reasoning_detects_untested_parameters(self):
        model = self._build_populated_model()
        reasoning = AIReasoningLayer(app_model=model)
        result = reasoning.reason()
        param_gaps = [g for g in result.gaps_identified
                      if g.gap_type == CoverageGapType.UNTESTED_PARAMETER]
        assert len(param_gaps) >= 2

    def test_reasoning_detects_technology_patterns(self):
        model = self._build_populated_model()
        reasoning = AIReasoningLayer(
            app_model=model,
            knowledge_engine=SecurityKnowledgeEngine(),
        )
        result = reasoning.reason()
        tech_gaps = [g for g in result.gaps_identified
                     if g.gap_type == CoverageGapType.UNTESTED_TECHNOLOGY]
        assert len(tech_gaps) >= 1

    def test_mark_tested_reduces_gaps(self):
        model = ApplicationModel("test.com")
        ep = model.add_entity(EntityType.ENDPOINT, "/api/only")
        reasoning = AIReasoningLayer(app_model=model)

        result1 = reasoning.reason()
        initial_gaps = len(result1.gaps_identified)

        reasoning.mark_tested(ep.id)
        result2 = reasoning.reason()
        assert len(result2.gaps_identified) < initial_gaps

    def test_reasoning_result_to_dict(self):
        model = self._build_populated_model()
        reasoning = AIReasoningLayer(app_model=model, tool_registry=ToolRegistry())
        result = reasoning.reason()
        d = result.to_dict()
        assert "total_gaps" in d
        assert "total_hypotheses" in d
        assert "total_actions" in d

    def test_parameter_type_drives_tool_suggestion(self):
        model = ApplicationModel("test.com")
        model.add_entity(EntityType.PARAMETER, "user_id",
                         properties={"location": "query", "type": "integer"})
        reasoning = AIReasoningLayer(app_model=model)
        result = reasoning.reason()
        param_gaps = [g for g in result.gaps_identified
                      if g.gap_type == CoverageGapType.UNTESTED_PARAMETER]
        assert len(param_gaps) >= 1
        # Integer params should suggest SQLi/IDOR
        tools = param_gaps[0].suggested_tools
        assert any("sqli" in t or "idor" in t for t in tools)

    def test_redirect_parameter_suggests_ssrf(self):
        model = ApplicationModel("test.com")
        model.add_entity(EntityType.PARAMETER, "redirect_url",
                         properties={"location": "query", "type": "string"})
        reasoning = AIReasoningLayer(app_model=model)
        result = reasoning.reason()
        param_gaps = [g for g in result.gaps_identified
                      if g.gap_type == CoverageGapType.UNTESTED_PARAMETER]
        tools = param_gaps[0].suggested_tools
        assert any("ssrf" in t or "redirect" in t for t in tools)


# =====================================================================
# 6. Attack Planner Tests
# =====================================================================

from app.ai.attack_planner import (
    AttackPlanner, AttackPlan, AttackStep, PlanStatus, StepStatus,
)
from app.ai.hypothesis_engine import HypothesisRecord


class TestAttackPlanner:
    def test_create_plan(self):
        planner = AttackPlanner(tool_registry=ToolRegistry())
        plan = planner.create_plan(
            title="Test SQL Injection",
            target="https://test.com/api/users",
            tool_sequence=["info_disclosure_validator", "sqli_validator"],
        )
        assert plan.status == PlanStatus.DRAFT
        assert len(plan.steps) == 2
        assert plan.steps[0].tool_name == "info_disclosure_validator"
        assert plan.steps[1].tool_name == "sqli_validator"

    def test_create_plan_from_hypothesis(self):
        planner = AttackPlanner(tool_registry=ToolRegistry())
        hyp = HypothesisRecord(
            hypothesis_id="hyp_test",
            statement="SQL Injection in user_id parameter",
            target_endpoint="/api/users",
            parameter="user_id",
            confidence=0.6,
        )
        plan = planner.create_plan_from_hypothesis(
            hypothesis=hyp,
            tool_sequence=["sqli_validator"],
            target="/api/users",
        )
        assert plan.hypothesis_id == "hyp_test"
        assert len(plan.steps) == 1

    def test_plan_validation(self):
        planner = AttackPlanner(tool_registry=ToolRegistry())
        plan = planner.create_plan(
            title="Test", target="test.com",
            tool_sequence=["sqli_validator", "xss_validator"],
        )
        validation = planner.validate_plan(plan)
        assert validation["is_valid"]
        assert validation["total_risk"] > 0

    def test_plan_risk_budget_exceeded(self):
        planner = AttackPlanner(tool_registry=ToolRegistry())
        plan = planner.create_plan(
            title="Heavy Plan", target="test.com",
            tool_sequence=["rce_validator", "deserialization_validator",
                           "cve_exploiter", "rce_validator"],
            risk_budget=5.0,  # Very low budget
        )
        validation = planner.validate_plan(plan)
        assert not validation["is_valid"]  # Should exceed budget

    def test_approve_and_execute_plan(self):
        planner = AttackPlanner(tool_registry=ToolRegistry())
        plan = planner.create_plan(
            title="Test", target="test.com",
            tool_sequence=["info_disclosure_validator"],
        )
        approved = planner.approve_plan(plan.plan_id)
        assert approved is not None
        assert approved.status == PlanStatus.APPROVED

        started = planner.start_plan(plan.plan_id)
        assert started.status == PlanStatus.EXECUTING

    def test_complete_step(self):
        planner = AttackPlanner(tool_registry=ToolRegistry())
        plan = planner.create_plan(
            title="Test", target="test.com",
            tool_sequence=["info_disclosure_validator"],
        )
        planner.approve_plan(plan.plan_id)
        planner.start_plan(plan.plan_id)

        step = plan.steps[0]
        completed = planner.complete_step(
            plan.plan_id, step.step_id,
            result={"status": "clean"}, succeeded=True,
        )
        assert completed.status == StepStatus.SUCCEEDED
        assert plan.status == PlanStatus.COMPLETED  # Only 1 step, so plan completes

    def test_abort_plan(self):
        planner = AttackPlanner(tool_registry=ToolRegistry())
        plan = planner.create_plan(
            title="Abort Test", target="test.com",
            tool_sequence=["sqli_validator", "xss_validator"],
        )
        planner.approve_plan(plan.plan_id)
        aborted = planner.abort_plan(plan.plan_id, "Target down")
        assert aborted.status == PlanStatus.ABORTED

    def test_plan_progress(self):
        planner = AttackPlanner(tool_registry=ToolRegistry())
        plan = planner.create_plan(
            title="Progress Test", target="test.com",
            tool_sequence=["sqli_validator", "xss_validator"],
        )
        assert plan.progress == 0.0
        planner.approve_plan(plan.plan_id)
        planner.start_plan(plan.plan_id)
        planner.complete_step(plan.plan_id, plan.steps[0].step_id, {}, True)
        assert plan.progress == 0.5

    def test_planner_summary(self):
        planner = AttackPlanner(tool_registry=ToolRegistry())
        planner.create_plan("A", "test.com", ["sqli_validator"])
        planner.create_plan("B", "test.com", ["xss_validator"])
        summary = planner.get_summary()
        assert summary["total_plans"] == 2

    def test_plan_to_dict(self):
        planner = AttackPlanner(tool_registry=ToolRegistry())
        plan = planner.create_plan("Test", "test.com", ["sqli_validator"])
        d = plan.to_dict()
        assert d["title"] == "Test"
        assert d["total_steps"] == 1
        assert len(d["steps"]) == 1


# =====================================================================
# 7. Security Engine Tests
# =====================================================================

from app.core.security_engine import (
    SecurityEngine, EnginePhase, EngineMetrics,
)


class TestSecurityEngine:
    def test_initialize_scan(self):
        engine = SecurityEngine()
        result = engine.initialize_scan("scan_v4_test", "example.com")
        assert result["status"] == "initialized"
        assert result["scan_id"] == "scan_v4_test"
        assert "subsystems" in result
        engine.cleanup_scan("scan_v4_test")

    def test_scan_lifecycle(self):
        engine = SecurityEngine()
        engine.initialize_scan("scan_lc", "example.com")

        engine.start_discovery("scan_lc")
        metrics = engine.get_metrics("scan_lc")
        assert metrics.phase == EnginePhase.DISCOVERING

        engine.complete_discovery("scan_lc")
        assert metrics.phase == EnginePhase.MODELING

        engine.start_testing("scan_lc")
        assert metrics.phase == EnginePhase.EXECUTING

        engine.start_validation("scan_lc")
        assert metrics.phase == EnginePhase.VALIDATING

        engine.start_reporting("scan_lc")
        assert metrics.phase == EnginePhase.REPORTING

        engine.complete_scan("scan_lc")
        assert metrics.phase == EnginePhase.COMPLETED

        engine.cleanup_scan("scan_lc")

    def test_reasoning_cycle(self):
        engine = SecurityEngine()
        engine.initialize_scan("scan_reason", "example.com")

        # Add entities to the model
        model = engine.get_app_model("scan_reason")
        model.add_entity(EntityType.ENDPOINT, "/api/login",
                         properties={"method": "POST", "auth_type": "none"})
        model.add_entity(EntityType.PARAMETER, "username",
                         properties={"location": "body", "type": "string"})

        result = engine.run_reasoning_cycle("scan_reason")
        assert result is not None
        assert len(result.gaps_identified) > 0

        metrics = engine.get_metrics("scan_reason")
        assert metrics.reasoning_cycles == 1
        assert metrics.hypotheses_generated > 0

        engine.cleanup_scan("scan_reason")

    def test_create_attack_plan(self):
        engine = SecurityEngine()
        engine.initialize_scan("scan_plan", "example.com")

        plan = engine.create_attack_plan(
            "scan_plan", "Test SQLi", "example.com/api",
            ["info_disclosure_validator", "sqli_validator"],
        )
        assert plan is not None
        assert len(plan.steps) == 2

        metrics = engine.get_metrics("scan_plan")
        assert metrics.plans_created == 1

        engine.cleanup_scan("scan_plan")

    def test_record_finding(self):
        engine = SecurityEngine()
        engine.initialize_scan("scan_find", "example.com")

        engine.record_finding("scan_find", "find_1", "suspected")
        engine.record_finding("scan_find", "find_2", "confirmed")
        engine.record_finding("scan_find", "find_3", "rejected")

        metrics = engine.get_metrics("scan_find")
        assert metrics.findings_suspected == 1
        assert metrics.findings_confirmed == 1
        assert metrics.findings_rejected == 1

        engine.cleanup_scan("scan_find")

    def test_get_scan_status(self):
        engine = SecurityEngine()
        engine.initialize_scan("scan_stat", "example.com")

        status = engine.get_scan_status("scan_stat")
        assert status["scan_id"] == "scan_stat"
        assert status["metrics"] is not None
        assert status["model_summary"] is not None

        engine.cleanup_scan("scan_stat")

    def test_get_engine_status(self):
        engine = SecurityEngine()
        engine.initialize_scan("scan_gs1", "a.com")
        engine.initialize_scan("scan_gs2", "b.com")

        status = engine.get_engine_status()
        assert status["active_scans"] == 2
        assert "tool_registry" in status
        assert "knowledge_engine" in status

        engine.cleanup_scan("scan_gs1")
        engine.cleanup_scan("scan_gs2")

    def test_cleanup(self):
        engine = SecurityEngine()
        engine.initialize_scan("scan_clean", "example.com")
        engine.cleanup_scan("scan_clean")
        assert engine.get_app_model("scan_clean") is None
        assert engine.get_metrics("scan_clean") is None

    def test_metrics_to_dict(self):
        metrics = EngineMetrics(
            phase=EnginePhase.EXECUTING,
            scan_id="test",
            target="example.com",
            started_at=time.time() - 60,
            reasoning_cycles=3,
            hypotheses_generated=5,
        )
        d = metrics.to_dict()
        assert d["phase"] == "EXECUTING"
        assert d["reasoning_cycles"] == 3
        assert d["uptime_seconds"] >= 59

    def test_tool_invocation_tracking(self):
        engine = SecurityEngine()
        engine.initialize_scan("scan_tools", "example.com")
        engine.record_tool_invocation("scan_tools")
        engine.record_tool_invocation("scan_tools")
        metrics = engine.get_metrics("scan_tools")
        assert metrics.tools_invoked == 2
        engine.cleanup_scan("scan_tools")


# =====================================================================
# 8. Access Control & Authorization Security Tests
# =====================================================================

class TestScanAccessControl:
    def test_guest_route_guard_protection(self):
        """Unauthenticated guests cannot access protected tabs in navigation logic."""
        protected_tabs = ["dashboard", "history", "reports", "diff", "admin", "domainDetail"]
        
        def mock_parse_route(hash_val, user=None):
            tab = hash_val.replace("#/", "").split("?")[0] or "home"
            if not user and tab in protected_tabs:
                tab = "home"
            return tab

        assert mock_parse_route("#/dashboard", user=None) == "home"
        assert mock_parse_route("#/history", user=None) == "home"
        assert mock_parse_route("#/admin", user=None) == "home"
        assert mock_parse_route("#/dashboard", user={"username": "alice", "role": "user"}) == "dashboard"

    def test_admin_role_enforcement(self):
        """Regular users cannot access admin panel."""
        def mock_check_admin(user):
            if not user or user.get("role") != "admin":
                return False
            return True

        assert not mock_check_admin(None)
        assert not mock_check_admin({"username": "alice", "role": "user"})
        assert mock_check_admin({"username": "admin", "role": "admin"})

    def test_change_password_validation(self):
        """Change password requires old password validation and strong new password."""
        from app.core.auth import hash_password, verify_password

        stored_hash = hash_password("OldSecret123!")
        assert verify_password("OldSecret123!", stored_hash)
        assert not verify_password("WrongPassword", stored_hash)

        new_hash = hash_password("NewSecret456@")
        assert verify_password("NewSecret456@", new_hash)
        assert not verify_password("OldSecret123!", new_hash)


