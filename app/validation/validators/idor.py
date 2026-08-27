"""Insecure Direct Object Reference (IDOR / BOLA) Validator (V10 Architecture).

Strict Principles:
1. GET /api/users/123 returning 200 OK for User 123 is NOT IDOR.
2. Public data access is NOT IDOR.
3. Requires multi-identity matrix proof: Actor A reading private Resource B belonging to Actor B.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Tuple

from app.validation.evidence.typed_evidence import (
    DifferentialObservation,
    EvidenceType,
    TypedEvidenceItem,
    TypedEvidencePackage,
)
from app.validation.result import NormalizedValidationResult
from app.validation.state_machine import FindingLifecycleState
from app.validation.validators.base import BaseVulnerabilityValidator

logger = logging.getLogger("validation.validators.idor")


class IDORValidator(BaseVulnerabilityValidator):
    """Validator evaluating Broken Object Level Authorization (IDOR)."""

    def __init__(self) -> None:
        super().__init__("idor")

    async def validate(
        self,
        target_url: str,
        finding_context: Dict[str, Any],
        session_context: Any,
    ) -> NormalizedValidationResult:
        param = finding_context.get("parameter", "id")
        raw_evidence = finding_context.get("raw_evidence", {}) or {}

        actor_a = raw_evidence.get("actor_a", "user_alpha")
        actor_b = raw_evidence.get("actor_b", "user_beta")
        resource_b_id = raw_evidence.get("resource_b_id", "rec_999")
        cross_access_succeeded = bool(raw_evidence.get("actor_a_accessed_resource_b", False))
        is_private_data = bool(raw_evidence.get("resource_contains_private_data", False))

        is_idor_confirmed = cross_access_succeeded and is_private_data

        pkg = TypedEvidencePackage(
            finding_id=finding_context.get("id", "idor_test"),
            vulnerability_type="idor",
            target_url=target_url,
            contract_id="idor",
            differential=DifferentialObservation(
                baseline_request={"actor": actor_b, "resource": resource_b_id},
                baseline_response={"status_code": 200, "owner": actor_b},
                test_request={"actor": actor_a, "resource": resource_b_id},
                test_response={"status_code": 200, "cross_access": cross_access_succeeded},
                differences=["Actor A accessed Actor B private resource" if is_idor_confirmed else "Single-user access or public resource"],
                significance_score=0.95 if is_idor_confirmed else 0.0,
                behavioral_anomaly_confirmed=is_idor_confirmed,
            ),
        )

        if is_idor_confirmed:
            pkg.items.append(
                TypedEvidenceItem(
                    evidence_type=EvidenceType.IDENTITY_CONTEXT,
                    title="Cross-Tenant Object Access Boundary Violation",
                    description=f"Actor '{actor_a}' read private object '{resource_b_id}' owned by '{actor_b}'.",
                    data={"actor_a": actor_a, "actor_b": actor_b, "resource_id": resource_b_id},
                    is_primary_proof=True,
                )
            )

        is_confirmed, status_state, conf_score = self.evaluate_evidence(pkg)

        if not is_confirmed:
            return NormalizedValidationResult(
                status=status_state,
                confidence="SUSPECTED" if status_state == FindingLifecycleState.INCONCLUSIVE.value else "OBSERVED",
                evidence_level="E0",
                vulnerability_type="idor",
                adapter_name="IDORValidator",
                title=f"Object Access on parameter '{param}' (Legitimate or Public)",
                severity="INFO",
                target_host=finding_context.get("target_host", ""),
                endpoint_url=target_url,
                parameter=param,
                actual_result="Resource access is either public, authenticated by the legitimate owner, or properly protected by authorization barriers.",
                expected_result="Multi-actor matrix proving unauthorized cross-tenant data access.",
            )

        return NormalizedValidationResult(
            status=FindingLifecycleState.CONFIRMED.value,
            confidence="CONFIRMED",
            evidence_level="E3",
            vulnerability_type="idor",
            adapter_name="IDORValidator",
            title=f"Broken Object Level Authorization (IDOR) on parameter '{param}'",
            severity="HIGH",
            target_host=finding_context.get("target_host", ""),
            endpoint_url=target_url,
            parameter=param,
            cwe_id="CWE-639",
            actual_result=f"Actor '{actor_a}' retrieved private object '{resource_b_id}' belonging to '{actor_b}' without authorization.",
            expected_result="Object-level authorization check: Verify authenticated user has explicit ownership of requested object.",
            remediation="Enforce object-level access controls in business logic validating record ownership against current session identity.",
            poc_command=f"curl -s -k -H 'Authorization: Bearer <TOKEN_ACTOR_A>' '{target_url}'",
        )

    def evaluate_evidence(self, evidence_pkg: TypedEvidencePackage) -> Tuple[bool, str, int]:
        diff = evidence_pkg.differential
        if not diff or not diff.behavioral_anomaly_confirmed:
            return False, FindingLifecycleState.REJECTED.value, 15
        return True, FindingLifecycleState.CONFIRMED.value, 94


idor_validator = IDORValidator()
