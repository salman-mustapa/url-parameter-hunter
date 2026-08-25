"""Comprehensive Unit and Integration Test Suite for Master Prompt v3 Engine.

Verifies:
1. Advanced JWT & 2FA/MFA Security Engine (§3.D, §9, §37)
2. IDOR Deep Lifecycle & Mass Assignment Engine (§4, §5, §38, §39)
3. Next-Best-Action Engine & Cost/Risk Optimization (§35, §36)
4. Finding Deduplication & Causal Chain Aggregation (§27, §30)
5. Section 42 Structured Specialist Response Format (§42)
"""

from __future__ import annotations

import unittest

from app.ai.decision_policy import (
    CandidateAction,
    InvestigationActionType,
    NextBestActionEngine,
    next_best_action_engine,
)
from app.findings.specialist_response import (
    CVSSProfile,
    CriticReviewSummary,
    FindingStatus,
    HypothesisSummary,
    IdentityContextSummary,
    ImpactAssessment,
    RootCauseAnalysis,
    SpecialistResponseV3,
    TargetLocation,
)
from app.validation.idor_lifecycle import (
    IdorLifecycleEngine,
    IdorLifecycleFinding,
    MassAssignmentFinding,
    ObjectOperation,
    idor_lifecycle_engine,
)
from app.validation.jwt_mfa_engine import JwtMfaFinding, JwtMfaSecurityEngine, jwt_mfa_engine


class TestMasterPromptV3Engine(unittest.TestCase):
    """Test suite covering all Master Prompt v3 autonomous pentest and attack chain components."""

    # ----------------------------------------------------------------------
    # 1. Advanced JWT & 2FA/MFA Security Engine
    # ----------------------------------------------------------------------
    def test_jwt_alg_none_and_2fa_takeover_attack_chain(self) -> None:
        # Sample base64url encoded standard JWT: {"alg": "HS256"}.{"sub": "alice", "role": "customer"}
        sample_jwt = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiYWxpY2UiLCAicm9sZSI6ICJjdXN0b21lciJ9.fake_signature_bytes"

        # 1. Test token forging with alg: none
        forged = jwt_mfa_engine.forge_alg_none_token(
            sample_jwt,
            override_claims={"sub": "admin@target.corp", "role": "admin", "isAdmin": True},
        )
        self.assertIsNotNone(forged)
        self.assertTrue(forged.endswith("."))

        # 2. Test chained attack simulation: JWT bypass -> 2FA reconfiguration
        def mock_jwt_verify(token: str):
            # Vulnerable server accepts alg:none
            return {"accepted": True, "user": "admin@target.corp"}

        def mock_2fa_setup(token: str, secret: str):
            # Vulnerable server commits 2FA under assumed identity
            return {"setup_success": True}

        chain_res = jwt_mfa_engine.evaluate_jwt_2fa_attack_chain(
            target_domain="auth.target.corp",
            original_user_token=sample_jwt,
            target_admin_identity="admin@target.corp",
            simulated_jwt_verify_fn=mock_jwt_verify,
            simulated_2fa_setup_fn=mock_2fa_setup,
        )

        self.assertIsInstance(chain_res, JwtMfaFinding)
        self.assertTrue(chain_res.is_chained)
        self.assertEqual(chain_res.severity, "CRITICAL")
        self.assertGreaterEqual(chain_res.confidence, 0.9)
        self.assertIn("attacker-configured second factor", chain_res.narrative)

    # ----------------------------------------------------------------------
    # 2. IDOR Deep Lifecycle & Mass Assignment Engine
    # ----------------------------------------------------------------------
    def test_idor_lifecycle_asymmetry_and_ownership_takeover(self) -> None:
        # Scenario: GET /api/doc/42 is blocked (403), but PUT /api/doc/42 accepts ownerId reassignment (200)
        def mock_get():
            return {"status_code": 403, "error": "Access Denied"}

        def mock_update(payload):
            return {"status_code": 200, "id": payload["id"], "ownerId": payload["ownerId"]}

        finding = idor_lifecycle_engine.evaluate_idor_lifecycle_asymmetry(
            endpoint_url="https://app.target.corp/api/doc/42",
            target_object_id="doc_42",
            requester_user="attacker_bob",
            owner_user="victim_alice",
            get_response_fn=mock_get,
            update_response_fn=mock_update,
        )

        self.assertIsInstance(finding, IdorLifecycleFinding)
        self.assertTrue(finding.ownership_takeover_confirmed)
        self.assertEqual(finding.severity, "CRITICAL")
        self.assertIn(ObjectOperation.UPDATE, finding.violated_operations)
        self.assertIn(ObjectOperation.OWNERSHIP_CHANGE, finding.violated_operations)
        self.assertIn("silently reassign object ownership", finding.narrative)

    def test_mass_assignment_sensitive_property_tampering(self) -> None:
        def mock_submit(payload):
            return {"status_code": 200, "user": {"id": 101, "role": payload.get("role")}}

        res = idor_lifecycle_engine.evaluate_mass_assignment(
            endpoint_url="https://app.target.corp/api/user/profile",
            property_name="role",
            tampered_value="admin",
            submit_fn=mock_submit,
        )

        self.assertIsInstance(res, MassAssignmentFinding)
        self.assertTrue(res.is_persisted)
        self.assertEqual(res.severity, "HIGH")
        self.assertIn("updated user role to 'admin'", res.state_change_observed)

    # ----------------------------------------------------------------------
    # 3. Next-Best-Action Utility Scoring & Ranking
    # ----------------------------------------------------------------------
    def test_next_best_action_scoring_and_ranking(self) -> None:
        # Candidate 1: High info gain, low cost
        action_sqli = CandidateAction(
            action_type=InvestigationActionType.VALIDATE,
            target_endpoint="/api/search",
            parameter="query",
            expected_info_gain=0.9,
            expected_security_impact=0.9,
            chain_potential=0.8,
            confidence_gain=0.8,
            request_cost=1.0,
            target_risk=1.0,
        )
        # Utility score = (0.9 + 0.9 + 0.8 + 0.8) / (1.0 + 1.0) = 3.4 / 2.0 = 1.70

        # Candidate 2: Low gain, heavy cost
        action_crawl = CandidateAction(
            action_type=InvestigationActionType.RECON,
            target_endpoint="/static/assets",
            parameter=None,
            expected_info_gain=0.2,
            expected_security_impact=0.1,
            chain_potential=0.1,
            confidence_gain=0.1,
            request_cost=5.0,
            target_risk=1.0,
        )
        # Utility score = (0.2 + 0.1 + 0.1 + 0.1) / (5.0 + 1.0) = 0.5 / 6.0 = 0.083

        ranked = next_best_action_engine.rank_candidate_actions([action_crawl, action_sqli])
        self.assertEqual(ranked[0].action_type, InvestigationActionType.VALIDATE)
        self.assertEqual(ranked[0].utility_score, 1.70)
        self.assertEqual(ranked[1].action_type, InvestigationActionType.RECON)

    # ----------------------------------------------------------------------
    # 4. Finding Deduplication & Causal Chain Aggregation
    # ----------------------------------------------------------------------
    def test_finding_deduplication_and_causal_chains(self) -> None:
        raw_findings = [
            {"finding_type": "business_logic", "title": "Negative Quantity in Cart", "severity": "HIGH"},
            {"finding_type": "business_logic", "title": "Wallet Balance Credited on Checkout", "severity": "HIGH"},
            {"finding_type": "business_logic", "title": "Inventory Count Increased", "severity": "MEDIUM"},
            {"finding_type": "xss", "title": "Reflected XSS on /search", "severity": "MEDIUM"},
        ]

        deduped = next_best_action_engine.deduplicate_and_chain_findings(raw_findings)
        self.assertEqual(len(deduped), 2)  # 1 chained business logic + 1 xss

        chained_biz = [f for f in deduped if f.get("is_chained")][0]
        self.assertEqual(chained_biz["severity"], "CRITICAL")
        self.assertIn("Chained Business Logic", chained_biz["title"])
        self.assertIn("Negative basket quantities bypass validation", chained_biz["summary"])

    # ----------------------------------------------------------------------
    # 5. Section 42 Specialist Response Schema
    # ----------------------------------------------------------------------
    def test_section_42_specialist_response_schema(self) -> None:
        response = SpecialistResponseV3(
            status=FindingStatus.CHAINED,
            title="Chained Authentication & Authorization: JWT Signature Bypass to 2FA Setup Takeover",
            vulnerability_type="jwt_signature_bypass_and_mfa_manipulation",
            severity="CRITICAL",
            confidence=0.97,
            target=TargetLocation(
                asset="auth.target.corp",
                endpoint="/api/v1/auth/2fa/setup",
                method="POST",
                parameter="Authorization",
            ),
            identity=IdentityContextSummary(
                requester="attacker@external.corp",
                role="customer",
                target_identity="admin@target.corp",
            ),
            hypothesis=HypothesisSummary(
                statement="JWT token parser fails to enforce algorithm allowlist, allowing alg:none forgery to reach 2FA setup.",
                supporting_evidence=["2FA setup succeeded with forged administrator identity token."],
            ),
            baseline={"status_code": 401, "error": "Unauthorized"},
            tests=[{"action": "Submit alg:none token to /2fa/setup", "status_code": 200}],
            observations=["Target application accepted forged JWT and enrolled attacker TOTP secret."],
            state_changes=[{"target_identity_2fa_status": "enrolled_with_attacker_totp"}],
            exploitability={"confirmed": True, "evidence": ["Demonstrated account takeover on admin@target.corp."]},
            impact=ImpactAssessment(
                confidentiality="CRITICAL",
                integrity="CRITICAL",
                availability="HIGH",
                authentication="Complete Authentication Bypass",
                authorization="Privilege Escalation to Administrator",
                business="Full administrative account takeover and organizational data compromise.",
            ),
            attack_chain=[
                {"step": 1, "description": "Forge unsigned JWT with alg:none and sub: admin@target.corp."},
                {"step": 2, "description": "Submit forged JWT to protected 2FA enrollment endpoint."},
                {"step": 3, "description": "Enroll attacker TOTP secret, locking legitimate admin out of 2FA workflow."},
            ],
            root_cause=RootCauseAnalysis(
                file="middleware/auth_jwt.py",
                line=45,
                function="verify_jwt_token",
                sink="jwt.decode(token, algorithms=['HS256', 'none'], verify=False)",
                explanation="Missing strict cryptographic algorithm verification and allowlist in JWT middleware.",
            ),
            evidence=[{"type": "http_request", "response_code": 200}],
            reproduction_steps=[
                "Forge JWT with alg:none and sub=admin@target.corp",
                "Send POST /api/v1/auth/2fa/setup with Authorization: Bearer <forged_token>",
                "Verify 2FA enrollment response with status 200",
            ],
            remediation=[
                "Explicitly restrict JWT algorithm allowlist strictly to ['RS256'] or ['HS256'].",
                "Ensure verify_signature=True is enforced in all JWT decoder configurations.",
                "Enforce secondary identity verification prior to any 2FA/MFA state changes.",
            ],
            cvss=CVSSProfile(
                score=9.8,
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                rationale="Unauthenticated attacker can forge arbitrary administrator tokens and seize full account control.",
            ),
            critic_review=CriticReviewSummary(
                status="passed",
                concerns=[],
            ),
        )

        out = response.to_dict()

        # Check mandatory Section 42 keys
        required_keys = [
            "status", "title", "vulnerability_type", "severity", "confidence",
            "target", "identity", "hypothesis", "baseline", "tests",
            "observations", "state_changes", "exploitability", "impact",
            "attack_chain", "root_cause", "evidence", "reproduction_steps",
            "remediation", "cvss", "critic_review"
        ]
        for key in required_keys:
            self.assertIn(key, out)

        self.assertEqual(out["identity"]["target_identity"], "admin@target.corp")
        self.assertEqual(out["status"], "chained")
        self.assertEqual(out["critic_review"]["status"], "passed")


if __name__ == "__main__":
    unittest.main()
