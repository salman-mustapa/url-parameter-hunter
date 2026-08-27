"""Remote Code Execution (RCE) Vulnerability-Specific Validator (V10 Architecture).

Strict Principles:
1. HTTP 500 alone is NOT RCE proof.
2. Parameter acceptance alone is NOT RCE proof.
3. Requires non-destructive canary marker execution proof.
4. Strictly forbids destructive commands.
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
from app.validation.safety.engine import safety_engine
from app.validation.state_machine import FindingLifecycleState
from app.validation.validators.base import BaseVulnerabilityValidator

logger = logging.getLogger("validation.validators.rce")


class RCEValidator(BaseVulnerabilityValidator):
    """Validator evaluating Remote Code Execution via safe canary echo verification."""

    def __init__(self) -> None:
        super().__init__("rce")

    async def validate(
        self,
        target_url: str,
        finding_context: Dict[str, Any],
        session_context: Any,
    ) -> NormalizedValidationResult:
        param = finding_context.get("parameter", "cmd")
        raw_evidence = finding_context.get("raw_evidence", {}) or {}

        body = str(raw_evidence.get("response_body", ""))
        canary_token = str(raw_evidence.get("canary_token", "VALIDATE_BENIGN_CANARY_123"))
        expected_output = str(raw_evidence.get("expected_output", "34b46c62b662df94d2bb776dfdd89ad5"))
        status_code = int(raw_evidence.get("status_code", 200))

        # Check: Did the server execute and return the pre-computed canary output?
        is_executed = expected_output in body or (canary_token in body and "echo " not in body)

        pkg = TypedEvidencePackage(
            finding_id=finding_context.get("id", "rce_test"),
            vulnerability_type="rce",
            target_url=target_url,
            contract_id="rce",
            differential=DifferentialObservation(
                baseline_request={"url": target_url},
                baseline_response={"status_code": 200},
                test_request={"param": param, "canary": canary_token},
                test_response={"status_code": status_code, "executed": is_executed},
                differences=["Pre-computed execution canary returned in response" if is_executed else "No execution output"],
                significance_score=1.0 if is_executed else 0.0,
                behavioral_anomaly_confirmed=is_executed,
            ),
        )

        if is_executed:
            pkg.items.append(
                TypedEvidenceItem(
                    evidence_type=EvidenceType.COMMAND_EXECUTION,
                    title="Benign Server-Side Code Execution Verified",
                    description=f"Server executed test payload and returned calculated token: {expected_output}",
                    data={"expected_output": expected_output},
                    is_primary_proof=True,
                )
            )

        is_confirmed, status_state, conf_score = self.evaluate_evidence(pkg)

        if not is_confirmed:
            return NormalizedValidationResult(
                status=status_state,
                confidence="SUSPECTED" if status_state == FindingLifecycleState.INCONCLUSIVE.value else "OBSERVED",
                evidence_level="E0",
                vulnerability_type="rce",
                adapter_name="RCEValidator",
                title=f"Potential Command Injection on '{param}' (Unconfirmed)",
                severity="INFO",
                target_host=finding_context.get("target_host", ""),
                endpoint_url=target_url,
                parameter=param,
                actual_result=f"Server returned HTTP {status_code} without executing benign test canary.",
                expected_result=f"Execution output matching calculated hash token '{expected_output}'.",
            )

        return NormalizedValidationResult(
            status=FindingLifecycleState.CONFIRMED.value,
            confidence="CONFIRMED",
            evidence_level="E4",
            vulnerability_type="rce",
            adapter_name="RCEValidator",
            title=f"Remote Code Execution (RCE) on parameter '{param}'",
            severity="CRITICAL",
            target_host=finding_context.get("target_host", ""),
            endpoint_url=target_url,
            parameter=param,
            cwe_id="CWE-94",
            actual_result=f"Server-side code execution proven via benign mathematical/echo canary '{expected_output}'.",
            expected_result="Command execution disabled; parameters passed strictly through safe APIs.",
            remediation="Avoid shell execution functions (exec, system, shell_exec). Use strict argument whitelisting.",
            poc_command=f"curl -s -k '{target_url}?{param}=echo%20{canary_token}'",
        )

    def evaluate_evidence(self, evidence_pkg: TypedEvidencePackage) -> Tuple[bool, str, int]:
        diff = evidence_pkg.differential
        if not diff or not diff.behavioral_anomaly_confirmed:
            return False, FindingLifecycleState.REJECTED.value, 10
        return True, FindingLifecycleState.CONFIRMED.value, 98


rce_validator = RCEValidator()
