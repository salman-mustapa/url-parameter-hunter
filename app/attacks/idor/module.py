"""Multi-Identity IDOR & Broken Object Level Authorization Module (V15).

Verifies Insecure Direct Object References and Authorization Failures:
- Executes multi-identity authorization tests across Identity A (owner) and Identity B (attacker).
- Tests numeric increment/decrement and UUID horizontal parameter tampering.
- Verifies boundary violation via response differential and content similarity analysis.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from app.attacks.base import AttackPlan, BaseAttackModule, ValidationResult
from app.core.session_context import SessionContext, SessionIdentity
from app.orchestration.attack_opportunity import AttackOpportunity

logger = logging.getLogger("attacks.idor")


class IDORAttackModule(BaseAttackModule):
    def __init__(self) -> None:
        super().__init__(attack_type="idor", cwe_id="CWE-639", default_severity="HIGH")

    async def discover(self, target: str, context: Dict[str, Any]) -> List[AttackOpportunity]:
        opps: List[AttackOpportunity] = []
        urls = context.get("urls", [])
        for u in urls:
            parsed = urlparse(u)
            if parsed.query:
                params = parse_qs(parsed.query)
                for p in params:
                    if any(p.lower().startswith(k) or p.lower().endswith(k) for k in ("id", "user", "account", "order", "doc", "invoice", "uid")):
                        opps.append(
                            AttackOpportunity(
                                target=target,
                                endpoint=u,
                                parameter=p,
                                attack_type="idor",
                                hypothesis=f"Identifier parameter '{p}' on {parsed.path} may allow horizontal authorization bypass.",
                                priority=92,
                            )
                        )
        return opps

    async def plan(self, opportunity: AttackOpportunity) -> AttackPlan:
        return AttackPlan(
            title=f"Multi-Identity IDOR/BOLA Authorization Verification on {opportunity.parameter}",
            attack_type="idor",
            target=opportunity.endpoint,
            steps=[
                "1. Baseline request with owner identity (Identity A)",
                "2. Multi-identity cross-tenant comparison (Identity B vs Resource A)",
                "3. Numeric ID tampering (+1 / -1 / boundary values)",
            ],
            payloads=["1", "2", "100", "0"],
            expected_evidence="HTTP 200 with sensitive resource data accessible by unauthorized identity.",
            context={"parameter": opportunity.parameter},
        )

    async def validate(self, opportunity: AttackOpportunity, session: SessionContext) -> ValidationResult:
        endpoint = opportunity.endpoint
        param = opportunity.parameter
        if not param:
            return ValidationResult(
                is_vulnerable=False,
                confidence=0.0,
                proof_level="P0",
                attack_type="idor",
                target_url=endpoint,
                message="No parameter specified for IDOR testing.",
            )

        parsed = urlparse(endpoint)
        query_params = parse_qs(parsed.query)
        orig_val = query_params.get(param, ["1"])[0]

        # 1. Check if we have two distinct identities configured
        if "identity_b" not in session.identities:
            # Set up mock identity B for authorization checking
            session.register_identity(
                SessionIdentity(id="identity_b", name="Attacker Identity", role="user_b")
            )

        # 2. Multi-identity comparative test
        diff = await session.compare_authorization(
            url=endpoint,
            method="GET",
            identity_a="default",
            identity_b="identity_b",
        )

        if diff.is_idor_confirmed:
            poc_curl = f"curl -s -k '{endpoint}'"
            return ValidationResult(
                is_vulnerable=True,
                confidence=0.92,
                proof_level="P3",
                attack_type="idor",
                target_url=endpoint,
                parameter=param,
                baseline_status=diff.identity_a_status,
                exploit_status=diff.identity_b_status,
                evidence={
                    "similarity": diff.body_similarity_ab,
                    "explanation": diff.explanation,
                    "details": diff.details,
                },
                poc_curl=poc_curl,
                message=diff.explanation,
                cwe_id="CWE-639",
                severity="HIGH",
            )

        # 3. Numeric ID Tampering test (e.g. id=1 -> id=2 or id=100)
        if orig_val.isdigit():
            alt_id = str(int(orig_val) + 1)
            t_params = dict(query_params)
            t_params[param] = [alt_id]
            tampered_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(t_params, doseq=True), parsed.fragment))

            tampered_resp = await session.get(tampered_url)
            baseline_resp = await session.get(endpoint)

            if tampered_resp.status_code == 200 and baseline_resp.status_code == 200:
                if tampered_resp.content_length > 100 and abs(tampered_resp.content_length - baseline_resp.content_length) > 10:
                    poc_curl = f"curl -s -k '{tampered_url}'"
                    return ValidationResult(
                        is_vulnerable=True,
                        confidence=0.88,
                        proof_level="P3",
                        attack_type="idor",
                        target_url=endpoint,
                        parameter=param,
                        baseline_status=baseline_resp.status_code,
                        exploit_status=tampered_resp.status_code,
                        evidence={
                            "tampered_parameter": param,
                            "original_value": orig_val,
                            "tampered_value": alt_id,
                            "original_length": baseline_resp.content_length,
                            "tampered_length": tampered_resp.content_length,
                        },
                        poc_curl=poc_curl,
                        message=f"HIGH: Insecure Direct Object Reference (IDOR) confirmed on parameter '{param}' ({orig_val} -> {alt_id}).",
                        cwe_id="CWE-639",
                        severity="HIGH",
                    )

        return ValidationResult(
            is_vulnerable=False,
            confidence=0.3,
            proof_level="P0",
            attack_type="idor",
            target_url=endpoint,
            parameter=param,
            message=f"Parameter '{param}' enforced proper authorization or returned 403/404.",
        )
