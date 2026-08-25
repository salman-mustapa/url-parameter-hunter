"""Unit and Integration Test Suite for Master Prompt v2 Engine.

Verifies:
1. AI World Model & Target Knowledge Graph (§4, §5)
2. Hypothesis Prioritization Formula & Decision Policy Engine (§3, §22, §23, §38)
3. Self-Critic Agent & Second-Pass Validation (§15, §16)
4. Security Invariant Engine & Multi-Step Stateful Chaining (L0-L5) (§7, §8, §9, §10, §20)
5. Finding Status Model & §39 Structured Specialist Response Format (§34, §39)
"""

from __future__ import annotations

import unittest

from app.ai.critic_agent import CriticDecision, SelfCriticAgent, critic_agent
from app.ai.hypothesis_engine import DecisionAction, HypothesisDecisionEngine, hypothesis_engine
from app.ai.security_invariants import (
    ChainedAttackPath,
    ExploitationDepthLevel,
    SecurityInvariantEngine,
    security_invariant_engine,
)
from app.ai.world_model import AIWorldModel, ai_world_model
from app.findings.specialist_response import (
    CVSSProfile,
    CriticReviewSummary,
    FindingStatus,
    HypothesisSummary,
    ImpactAssessment,
    RootCauseAnalysis,
    SpecialistResponseV2,
    TargetLocation,
)


class TestMasterPromptV2Engine(unittest.TestCase):
    """Test suite covering the Master Prompt v2 AI Attack Investigation Engine."""

    def setUp(self) -> None:
        ai_world_model.reset()
        hypothesis_engine.reset()

    # ----------------------------------------------------------------------
    # 1. AI World Model & Target Knowledge Graph
    # ----------------------------------------------------------------------
    def test_ai_world_model_and_graph(self) -> None:
        app_node = ai_world_model.upsert_node(
            node_id="app_1",
            category="Application",
            label="ShopApp",
            framework="FastAPI",
        )
        endpoint_node = ai_world_model.upsert_node(
            node_id="ep_1",
            category="Endpoint",
            label="/api/v1/checkout",
            method="POST",
        )
        user_node = ai_world_model.upsert_node(
            node_id="usr_1",
            category="Identity",
            label="customer_alice",
            role="customer",
        )

        edge = ai_world_model.add_relation(
            source_id="app_1",
            target_id="ep_1",
            relation="EXPOSES",
        )
        self.assertIsNotNone(edge)

        ai_world_model.record_state_transition(
            from_entity_id="ep_1",
            to_entity_id="usr_1",
            action="wallet_mutation",
            state_mutation={"balance_delta": +50.0},
        )

        graph = ai_world_model.get_attack_graph_summary()
        self.assertEqual(graph["total_nodes"], 3)
        self.assertEqual(graph["total_edges"], 2)
        self.assertIn("/api/v1/checkout", ai_world_model.endpoints_index)

    # ----------------------------------------------------------------------
    # 2. Hypothesis Prioritization Formula & Decision Policy
    # ----------------------------------------------------------------------
    def test_hypothesis_prioritization_and_decision_policy(self) -> None:
        hyp_sqli = hypothesis_engine.create_hypothesis(
            statement="Parameter 'email' on /login is vulnerable to SQL injection auth bypass.",
            target_endpoint="/login",
            parameter="email",
            initial_confidence=0.7,
            exploitability=0.9,
            impact=0.9,
            chain_potential=0.8,
            business_criticality=0.8,
        )

        self.assertAlmostEqual(hyp_sqli.priority_score, 0.835, places=2)

        action = hypothesis_engine.decide_next_action(hyp_sqli)
        self.assertEqual(action, DecisionAction.ESCALATE)

        hypothesis_engine.update_hypothesis_result(
            hypothesis_id=hyp_sqli.hypothesis_id,
            observed_result={"status_code": 200, "auth_token": "token_admin"},
            is_supported=True,
            evidence_note="Authentication bypass achieved with admin session returned.",
        )
        self.assertGreaterEqual(hyp_sqli.confidence, 0.95)
        new_action = hypothesis_engine.decide_next_action(hyp_sqli)
        self.assertEqual(new_action, DecisionAction.CHAIN)

    # ----------------------------------------------------------------------
    # 3. Self-Critic Agent & Second-Pass Validation
    # ----------------------------------------------------------------------
    def test_self_critic_adversarial_review_and_second_pass(self) -> None:
        waf_review = critic_agent.review_finding(
            vulnerability_type="SQL Injection",
            target_endpoint="https://target.corp/login",
            baseline_state={"status_code": 200},
            observed_test_result={"status_code": 403, "body": "Cloudflare Attention Required: Ray ID 12345"},
            claimed_severity="HIGH",
        )
        self.assertEqual(waf_review.status, CriticDecision.REJECTED)
        self.assertFalse(waf_review.is_confirmed)
        self.assertTrue(any("WAF" in c for c in waf_review.concerns))

        valid_review = critic_agent.review_finding(
            vulnerability_type="SQL Injection",
            target_endpoint="https://target.corp/login",
            baseline_state={"status_code": 401},
            observed_test_result={"status_code": 200, "body": "Welcome Admin Dashboard", "impact_proven": True},
            claimed_severity="CRITICAL",
            reproduction_verified=True,
        )
        self.assertEqual(valid_review.status, CriticDecision.PASSED)
        self.assertTrue(valid_review.is_confirmed)

        def mock_base():
            return {"status_code": 401}
        def mock_test():
            return {"status_code": 200, "is_anomalous": True}

        second_pass_ok = critic_agent.execute_second_pass_validation(
            target_endpoint="https://target.corp/login",
            test_fn=mock_test,
            baseline_fn=mock_base,
        )
        self.assertTrue(second_pass_ok)

    # ----------------------------------------------------------------------
    # 4. Security Invariant Engine & Stateful Chaining (L0-L5)
    # ----------------------------------------------------------------------
    def test_security_invariant_stateful_chaining_l5(self) -> None:
        chain = security_invariant_engine.evaluate_e_commerce_chained_invariant(
            target_url="https://shop.corp.com/api/cart",
            submitted_quantity=-6,
            unit_price=25.0,
            initial_wallet_balance=100.0,
            initial_inventory_stock=50,
        )

        self.assertIsInstance(chain, ChainedAttackPath)
        self.assertEqual(chain.depth_reached, ExploitationDepthLevel.L5_CHAINED_IMPACT)
        self.assertEqual(len(chain.steps), 4)
        self.assertIn("wallet balance increased", chain.steps[2]["observed"].lower())
        self.assertIn("inventory stock increased", chain.steps[3]["observed"].lower())

        idor_violation = security_invariant_engine.check_ownership_invariant(
            authenticated_user_id="user_alice",
            target_resource_owner_id="user_bob",
            access_granted=True,
        )
        self.assertIsNotNone(idor_violation)
        self.assertEqual(idor_violation.depth_level, ExploitationDepthLevel.L4_SECURITY_IMPACT)

    # ----------------------------------------------------------------------
    # 5. Finding Status Model & §39 Structured Response Format
    # ----------------------------------------------------------------------
    def test_section_39_specialist_response_schema(self) -> None:
        response = SpecialistResponseV2(
            status=FindingStatus.CHAINED,
            title="Chained Business Logic: Negative Quantity to Wallet Credit & Inventory Inflation",
            vulnerability_type="business_logic_invariant_flaw",
            severity="CRITICAL",
            confidence=0.98,
            target=TargetLocation(
                asset="shop.corp.com",
                endpoint="/api/cart/add",
                method="POST",
                parameter="quantity",
            ),
            hypothesis=HypothesisSummary(
                statement="Negative quantity bypasses checkout upper-bound validation and mutates downstream wallet transactions.",
                supporting_evidence=["Observed positive balance delta on checkout confirmation."],
            ),
            baseline={"status_code": 200, "cart_total": 50.0},
            tests=[{"payload": {"quantity": -6}, "status_code": 200}],
            observations=["Wallet credited by $150.00.", "Inventory stock increased by 6."],
            state_changes=[{"wallet_balance": "+150.00"}, {"inventory_stock": "+6"}],
            exploitability={"confirmed": True, "evidence": ["Demonstrated $150 credit on test account."]},
            impact=ImpactAssessment(
                confidentiality="LOW",
                integrity="CRITICAL",
                availability="LOW",
                business="Direct financial loss via unauthorized wallet minting.",
            ),
            attack_chain=[
                {"step": 1, "description": "Negative quantity accepted into cart."},
                {"step": 2, "description": "Order total evaluated to -$150.00."},
                {"step": 3, "description": "Wallet credited with absolute value."},
            ],
            root_cause=RootCauseAnalysis(
                file="services/cart_service.py",
                line=88,
                function="add_item_to_cart",
                sink="models.Cart.quantity = req.quantity",
                explanation="Missing strict positive integer validation (quantity > 0) in basket validation service.",
            ),
            evidence=[{"type": "http_trace", "response_status": 200}],
            reproduction_steps=[
                "POST /api/cart/add with quantity: -6",
                "POST /api/checkout/process to complete transaction",
                "GET /api/user/wallet to verify balance increase",
            ],
            remediation=[
                "Enforce strict server-side validation: quantity MUST be an integer > 0.",
                "Enforce database check constraints (CHECK quantity > 0).",
                "Add automated regression tests in checkout pipeline.",
            ],
            cvss=CVSSProfile(
                score=9.1,
                vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H",
                rationale="Unauthenticated or low-privilege customer can execute arbitrary balance tampering.",
            ),
            critic_review=CriticReviewSummary(
                status="passed",
                concerns=[],
            ),
        )

        out = response.to_dict()
        required_keys = [
            "status", "title", "vulnerability_type", "severity", "confidence",
            "target", "hypothesis", "baseline", "tests", "observations",
            "state_changes", "exploitability", "impact", "attack_chain",
            "root_cause", "evidence", "reproduction_steps", "remediation",
            "cvss", "critic_review"
        ]
        for key in required_keys:
            self.assertIn(key, out)

        self.assertEqual(out["status"], "chained")
        self.assertEqual(out["target"]["endpoint"], "/api/cart/add")
        self.assertEqual(out["critic_review"]["status"], "passed")


if __name__ == "__main__":
    unittest.main()
