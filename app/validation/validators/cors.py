"""CORS Misconfiguration Vulnerability-Specific Validator (V10 Architecture).

Strict Principles:
1. Access-Control-Allow-Origin: * without Allow-Credentials is NOT an exploitable finding on public endpoints.
2. Requires arbitrary untrusted Origin reflection AND Access-Control-Allow-Credentials: true on authenticated sensitive routes.
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

logger = logging.getLogger("validation.validators.cors")


class CORSValidator(BaseVulnerabilityValidator):
    """Validator evaluating Cross-Origin Resource Sharing (CORS) Misconfigurations."""

    def __init__(self) -> None:
        super().__init__("cors")

    async def validate(
        self,
        target_url: str,
        finding_context: Dict[str, Any],
        session_context: Any,
    ) -> NormalizedValidationResult:
        raw_evidence = finding_context.get("raw_evidence", {}) or {}

        origin_header = str(raw_evidence.get("injected_origin", "https://evil.example.com"))
        allow_origin_hdr = str(raw_evidence.get("allow_origin_header", ""))
        allow_credentials = bool(raw_evidence.get("allow_credentials_header", False))
        is_sensitive_endpoint = bool(raw_evidence.get("endpoint_is_authenticated_sensitive", False))

        is_origin_reflected = origin_header in allow_origin_hdr or allow_origin_hdr == "null"
        is_exploitable_cors = is_origin_reflected and allow_credentials and is_sensitive_endpoint

        pkg = TypedEvidencePackage(
            finding_id=finding_context.get("id", "cors_test"),
            vulnerability_type="cors",
            target_url=target_url,
            contract_id="cors",
            differential=DifferentialObservation(
                baseline_request={"url": target_url},
                baseline_response={"status_code": 200},
                test_request={"Origin": origin_header},
                test_response={"allow_origin": allow_origin_hdr, "allow_credentials": allow_credentials},
                differences=["Arbitrary Origin reflected with Allow-Credentials: true on private API" if is_exploitable_cors else "Safe or public CORS configuration"],
                significance_score=0.9 if is_exploitable_cors else 0.0,
                behavioral_anomaly_confirmed=is_exploitable_cors,
            ),
        )

        if is_exploitable_cors:
            pkg.items.append(
                TypedEvidenceItem(
                    evidence_type=EvidenceType.HTTP_RESPONSE,
                    title="Arbitrary Origin Reflected with Allow-Credentials: True",
                    description=f"Server returned Access-Control-Allow-Origin: {allow_origin_hdr} with Allow-Credentials: true.",
                    data={"origin": origin_header, "allow_origin": allow_origin_hdr, "allow_credentials": True},
                    is_primary_proof=True,
                )
            )

        is_confirmed, status_state, conf_score = self.evaluate_evidence(pkg)

        if not is_confirmed:
            return NormalizedValidationResult(
                status=status_state,
                confidence="SUSPECTED" if status_state == FindingLifecycleState.INCONCLUSIVE.value else "OBSERVED",
                evidence_level="E0",
                vulnerability_type="cors",
                adapter_name="CORSValidator",
                title="Public or Safe CORS Policy (Not Exploitable)",
                severity="INFO",
                target_host=finding_context.get("target_host", ""),
                endpoint_url=target_url,
                actual_result="CORS configuration either uses safe wildcard on public data or does not permit credentials.",
                expected_result="Origin reflection with Access-Control-Allow-Credentials: true on authenticated private endpoint.",
            )

        return NormalizedValidationResult(
            status=FindingLifecycleState.CONFIRMED.value,
            confidence="CONFIRMED",
            evidence_level="E3",
            vulnerability_type="cors",
            adapter_name="CORSValidator",
            title="Exploitable Cross-Origin Resource Sharing (CORS) Misconfiguration",
            severity="MEDIUM",
            target_host=finding_context.get("target_host", ""),
            endpoint_url=target_url,
            cwe_id="CWE-942",
            actual_result=f"Arbitrary origin '{origin_header}' reflected with credentials allowed on sensitive endpoint.",
            expected_result="Strict whitelist of allowed trusted origins for authenticated cross-origin requests.",
            remediation="Enforce a strict whitelist of trusted origin domains; do not reflect untrusted Origin headers dynamically when credentials are supported.",
            poc_command=f"curl -s -k -H 'Origin: {origin_header}' -I '{target_url}'",
        )

    def evaluate_evidence(self, evidence_pkg: TypedEvidencePackage) -> Tuple[bool, str, int]:
        diff = evidence_pkg.differential
        if not diff or not diff.behavioral_anomaly_confirmed:
            return False, FindingLifecycleState.REJECTED.value, 15
        return True, FindingLifecycleState.CONFIRMED.value, 90


cors_validator = CORSValidator()
