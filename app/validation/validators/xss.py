"""Cross-Site Scripting (XSS) Vulnerability-Specific Validator (V10 Architecture).

Strict Principles:
1. Reflected parameter alone is NOT XSS.
2. HTML-entity encoded reflection (&lt;script&gt;) is NOT XSS.
3. Content-Type application/json reflection is NOT XSS.
4. Requires unencoded special characters (<, >, ", ') in executable HTML context.
"""

from __future__ import annotations

import logging
import re
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

logger = logging.getLogger("validation.validators.xss")


class XSSValidator(BaseVulnerabilityValidator):
    """Validator evaluating Cross-Site Scripting via context & encoding analysis."""

    def __init__(self) -> None:
        super().__init__("xss")

    async def validate(
        self,
        target_url: str,
        finding_context: Dict[str, Any],
        session_context: Any,
    ) -> NormalizedValidationResult:
        param = finding_context.get("parameter", "q")
        raw_evidence = finding_context.get("raw_evidence", {}) or {}

        body = str(raw_evidence.get("response_body", ""))
        content_type = str(raw_evidence.get("content_type", "text/html")).lower()
        payload = str(raw_evidence.get("payload", "<script>alert(1)</script>"))

        # Check 1: Is payload reflected?
        is_reflected = payload in body

        # Check 2: Is it HTML entity encoded? (e.g. &lt;script&gt; or &quot;)
        encoded_payload = payload.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")
        is_encoded = ("&lt;" in body or "&gt;" in body or "&quot;" in body or "&#" in body) and (encoded_payload in body or "&lt;script" in body)

        # Check 3: Is it in non-executable JSON/Plaintext content-type?
        is_non_executable_mime = "application/json" in content_type or "text/plain" in content_type

        # Check 4: Unencoded executable reflection
        is_executable = is_reflected and not is_encoded and not is_non_executable_mime

        pkg = TypedEvidencePackage(
            finding_id=finding_context.get("id", "xss_test"),
            vulnerability_type="xss",
            target_url=target_url,
            contract_id="xss",
            differential=DifferentialObservation(
                baseline_request={"url": target_url},
                baseline_response={"content_type": content_type},
                test_request={"payload": payload, "param": param},
                test_response={"content_type": content_type, "reflected": is_reflected},
                differences=["Unencoded payload reflected in DOM" if is_executable else "Safely encoded or non-executable"],
                significance_score=0.95 if is_executable else 0.0,
                behavioral_anomaly_confirmed=is_executable,
            ),
        )

        if is_executable:
            pkg.items.append(
                TypedEvidenceItem(
                    evidence_type=EvidenceType.REFLECTION,
                    title="Unencoded Executable Reflection in HTML DOM",
                    description="Raw unencoded script/tag characters reflected in response body.",
                    data={"payload": payload, "content_type": content_type},
                    is_primary_proof=True,
                )
            )

        is_confirmed, status_state, conf_score = self.evaluate_evidence(pkg)

        if not is_confirmed:
            reason = "Reflection is properly HTML-entity encoded." if is_encoded else (
                "Response served with non-executable MIME type (application/json)." if is_non_executable_mime else
                "Parameter was not reflected in executable HTML context."
            )
            return NormalizedValidationResult(
                status=status_state,
                confidence="SUSPECTED" if status_state == FindingLifecycleState.INCONCLUSIVE.value else "OBSERVED",
                evidence_level="E0",
                vulnerability_type="xss",
                adapter_name="XSSValidator",
                title=f"Non-Executable Reflection on '{param}' (Safe)",
                severity="INFO",
                target_host=finding_context.get("target_host", ""),
                endpoint_url=target_url,
                parameter=param,
                actual_result=reason,
                expected_result="Raw executable tag injection in text/html context.",
            )

        return NormalizedValidationResult(
            status=FindingLifecycleState.CONFIRMED.value,
            confidence="CONFIRMED",
            evidence_level="E3",
            vulnerability_type="xss",
            adapter_name="XSSValidator",
            title=f"Reflected Cross-Site Scripting (XSS) on '{param}'",
            severity="MEDIUM",
            target_host=finding_context.get("target_host", ""),
            endpoint_url=target_url,
            parameter=param,
            cwe_id="CWE-79",
            actual_result=f"Unencoded HTML payload '{payload}' reflected directly into browser DOM context.",
            expected_result="Context-aware HTML entity encoding or Content-Security-Policy enforcement.",
            remediation="Implement context-aware HTML entity encoding (htmlspecialchars with ENT_QUOTES) and strict CSP.",
            poc_command=f"curl -s -k '{target_url}?{param}={payload}'",
        )

    def evaluate_evidence(self, evidence_pkg: TypedEvidencePackage) -> Tuple[bool, str, int]:
        diff = evidence_pkg.differential
        if not diff or not diff.behavioral_anomaly_confirmed:
            return False, FindingLifecycleState.REJECTED.value, 15
        return True, FindingLifecycleState.CONFIRMED.value, 90


xss_validator = XSSValidator()
