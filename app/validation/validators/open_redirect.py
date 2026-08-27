"""Unvalidated Open Redirect Validator (V10 Architecture).

Strict Principles:
1. Same-origin redirect (/dashboard) is NOT Open Redirect.
2. Relative redirect is NOT Open Redirect.
3. Requires HTTP 3xx Location header containing user-controlled external host.
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse
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

logger = logging.getLogger("validation.validators.open_redirect")


class OpenRedirectValidator(BaseVulnerabilityValidator):
    """Validator evaluating Open Redirect vulnerabilities."""

    def __init__(self) -> None:
        super().__init__("open_redirect")

    async def validate(
        self,
        target_url: str,
        finding_context: Dict[str, Any],
        session_context: Any,
    ) -> NormalizedValidationResult:
        param = finding_context.get("parameter", "url")
        raw_evidence = finding_context.get("raw_evidence", {}) or {}

        location_hdr = str(raw_evidence.get("location_header", ""))
        target_domain = str(raw_evidence.get("injected_domain", "https://attacker.example.com"))
        target_parsed = urlparse(target_url)

        # Check: Is Location header redirecting to external untrusted origin?
        loc_parsed = urlparse(location_hdr)
        is_external = bool(loc_parsed.netloc and loc_parsed.netloc != target_parsed.netloc and not loc_parsed.netloc.endswith(target_parsed.netloc))
        is_open_redirect = is_external and target_domain in location_hdr

        pkg = TypedEvidencePackage(
            finding_id=finding_context.get("id", "redirect_test"),
            vulnerability_type="open_redirect",
            target_url=target_url,
            contract_id="open_redirect",
            differential=DifferentialObservation(
                baseline_request={"url": target_url},
                baseline_response={"status_code": 200},
                test_request={"param": param, "target": target_domain},
                test_response={"location": location_hdr, "is_external": is_external},
                differences=["Location header redirected to external host" if is_open_redirect else "Internal / sanitized redirect"],
                significance_score=0.9 if is_open_redirect else 0.0,
                behavioral_anomaly_confirmed=is_open_redirect,
            ),
        )

        if is_open_redirect:
            pkg.items.append(
                TypedEvidenceItem(
                    evidence_type=EvidenceType.HTTP_RESPONSE,
                    title="External Host in Location Header",
                    description=f"Server returned Location header redirecting to external domain: {location_hdr}",
                    data={"location": location_hdr},
                    is_primary_proof=True,
                )
            )

        is_confirmed, status_state, conf_score = self.evaluate_evidence(pkg)

        if not is_confirmed:
            return NormalizedValidationResult(
                status=status_state,
                confidence="SUSPECTED" if status_state == FindingLifecycleState.INCONCLUSIVE.value else "OBSERVED",
                evidence_level="E0",
                vulnerability_type="open_redirect",
                adapter_name="OpenRedirectValidator",
                title=f"Internal / Sanitized Redirect on '{param}' (Safe)",
                severity="INFO",
                target_host=finding_context.get("target_host", ""),
                endpoint_url=target_url,
                parameter=param,
                actual_result="Redirect stays strictly within same origin / relative path or input was sanitized.",
                expected_result="Location header pointing directly to untrusted external destination domain.",
            )

        return NormalizedValidationResult(
            status=FindingLifecycleState.CONFIRMED.value,
            confidence="CONFIRMED",
            evidence_level="E3",
            vulnerability_type="open_redirect",
            adapter_name="OpenRedirectValidator",
            title=f"Unvalidated Open Redirect on parameter '{param}'",
            severity="MEDIUM",
            target_host=finding_context.get("target_host", ""),
            endpoint_url=target_url,
            parameter=param,
            cwe_id="CWE-601",
            actual_result=f"Location header redirected directly to external target '{location_hdr}'.",
            expected_result="Validate redirect targets against strict internal route whitelist.",
            remediation="Enforce relative path redirects or strict whitelist of allowable external target domains.",
            poc_command=f"curl -s -k -I '{target_url}?{param}={target_domain}'",
        )

    def evaluate_evidence(self, evidence_pkg: TypedEvidencePackage) -> Tuple[bool, str, int]:
        diff = evidence_pkg.differential
        if not diff or not diff.behavioral_anomaly_confirmed:
            return False, FindingLifecycleState.REJECTED.value, 15
        return True, FindingLifecycleState.CONFIRMED.value, 90


open_redirect_validator = OpenRedirectValidator()
