"""Server-Side Request Forgery (SSRF) Vulnerability-Specific Validator (V10 Architecture).

Strict Principles:
1. URL parameter accepted (HTTP 200) alone is NOT SSRF.
2. Generic 400/500 on invalid URL is NOT SSRF.
3. Requires verified internal resource content or differential network connectivity proof.
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

logger = logging.getLogger("validation.validators.ssrf")


class SSRFValidator(BaseVulnerabilityValidator):
    """Validator evaluating Server-Side Request Forgery."""

    def __init__(self) -> None:
        super().__init__("ssrf")

    async def validate(
        self,
        target_url: str,
        finding_context: Dict[str, Any],
        session_context: Any,
    ) -> NormalizedValidationResult:
        param = finding_context.get("parameter", "url")
        raw_evidence = finding_context.get("raw_evidence", {}) or {}

        body = str(raw_evidence.get("response_body", ""))
        fetched_internal = bool(raw_evidence.get("internal_resource_fetched", False))
        is_cloud_metadata = ("ami-id" in body or "instance-id" in body or "computeMetadata" in body)

        is_ssrf_proven = fetched_internal or is_cloud_metadata

        pkg = TypedEvidencePackage(
            finding_id=finding_context.get("id", "ssrf_test"),
            vulnerability_type="ssrf",
            target_url=target_url,
            contract_id="ssrf",
            differential=DifferentialObservation(
                baseline_request={"url": target_url},
                baseline_response={"status_code": 200},
                test_request={"param": param, "target": "127.0.0.1:80"},
                test_response={"internal_fetched": is_ssrf_proven},
                differences=["Internal service content exposed" if is_ssrf_proven else "Parameter accepted without internal fetch"],
                significance_score=0.95 if is_ssrf_proven else 0.0,
                behavioral_anomaly_confirmed=is_ssrf_proven,
            ),
        )

        if is_ssrf_proven:
            pkg.items.append(
                TypedEvidenceItem(
                    evidence_type=EvidenceType.RESOURCE_ACCESS,
                    title="Internal Host / Metadata Resource Disclosed",
                    description="Server fetched and returned internal restricted network content.",
                    data={"metadata_detected": is_cloud_metadata},
                    is_primary_proof=True,
                )
            )

        is_confirmed, status_state, conf_score = self.evaluate_evidence(pkg)

        if not is_confirmed:
            return NormalizedValidationResult(
                status=status_state,
                confidence="SUSPECTED" if status_state == FindingLifecycleState.INCONCLUSIVE.value else "OBSERVED",
                evidence_level="E0",
                vulnerability_type="ssrf",
                adapter_name="SSRFValidator",
                title=f"URL Parameter on '{param}' (Unconfirmed SSRF)",
                severity="INFO",
                target_host=finding_context.get("target_host", ""),
                endpoint_url=target_url,
                parameter=param,
                actual_result="Server accepted URL parameter but did not expose internal network resources or cloud metadata.",
                expected_result="Internal network interaction or out-of-band callback confirmation.",
            )

        return NormalizedValidationResult(
            status=FindingLifecycleState.CONFIRMED.value,
            confidence="CONFIRMED",
            evidence_level="E3",
            vulnerability_type="ssrf",
            adapter_name="SSRFValidator",
            title=f"Server-Side Request Forgery (SSRF) on parameter '{param}'",
            severity="HIGH",
            target_host=finding_context.get("target_host", ""),
            endpoint_url=target_url,
            parameter=param,
            cwe_id="CWE-918",
            actual_result="Server fetched internal restricted resource / metadata through unvalidated URL parameter.",
            expected_result="Strict IP/domain whitelisting and disabling request forwarding to private IP ranges (RFC 1918).",
            remediation="Enforce strict URL destination whitelisting and block access to 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, and 169.254.169.254.",
            poc_command=f"curl -s -k '{target_url}?{param}=http://127.0.0.1/'",
        )

    def evaluate_evidence(self, evidence_pkg: TypedEvidencePackage) -> Tuple[bool, str, int]:
        diff = evidence_pkg.differential
        if not diff or not diff.behavioral_anomaly_confirmed:
            return False, FindingLifecycleState.REJECTED.value, 20
        return True, FindingLifecycleState.CONFIRMED.value, 92


ssrf_validator = SSRFValidator()
