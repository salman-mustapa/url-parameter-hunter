"""Authentication Bypass Vulnerability-Specific Validator (V10 Architecture).

Strict Principles:
1. Login page returning HTTP 200 is NOT authentication bypass.
2. Public landing page or static asset returning HTTP 200 is NOT authentication bypass.
3. Requires proof that a protected administrative or private functional route is accessed without credentials.
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

logger = logging.getLogger("validation.validators.auth_bypass")


class AuthBypassValidator(BaseVulnerabilityValidator):
    """Validator evaluating Authentication Bypass."""

    def __init__(self) -> None:
        super().__init__("auth_bypass")

    async def validate(
        self,
        target_url: str,
        finding_context: Dict[str, Any],
        session_context: Any,
    ) -> NormalizedValidationResult:
        raw_evidence = finding_context.get("raw_evidence", {}) or {}

        is_login_page = bool(raw_evidence.get("is_login_or_public_page", False))
        protected_data_accessed = bool(raw_evidence.get("protected_admin_data_accessed", False))
        bypass_header_used = str(raw_evidence.get("bypass_header", "X-Forwarded-For: 127.0.0.1"))
        baseline_status = int(raw_evidence.get("baseline_unauthorized_status", 401))

        # Check: Did unauthenticated request actually access protected functionality?
        is_bypass_confirmed = protected_data_accessed and not is_login_page and (baseline_status in (401, 403, 302))

        pkg = TypedEvidencePackage(
            finding_id=finding_context.get("id", "auth_bypass_test"),
            vulnerability_type="auth_bypass",
            target_url=target_url,
            contract_id="auth_bypass",
            differential=DifferentialObservation(
                baseline_request={"url": target_url, "auth": "none"},
                baseline_response={"status_code": baseline_status},
                test_request={"url": target_url, "header": bypass_header_used},
                test_response={"status_code": 200, "protected_data_accessed": protected_data_accessed},
                differences=["Protected admin route accessible unauthenticated" if is_bypass_confirmed else "Public page or login form"],
                significance_score=1.0 if is_bypass_confirmed else 0.0,
                behavioral_anomaly_confirmed=is_bypass_confirmed,
            ),
        )

        if is_bypass_confirmed:
            pkg.items.append(
                TypedEvidenceItem(
                    evidence_type=EvidenceType.AUTH_STATE,
                    title="Protected Admin Route Accessible Unauthenticated",
                    description=f"Server returned private administration data using bypass vector: {bypass_header_used}.",
                    data={"bypass_vector": bypass_header_used},
                    is_primary_proof=True,
                )
            )

        is_confirmed, status_state, conf_score = self.evaluate_evidence(pkg)

        if not is_confirmed:
            return NormalizedValidationResult(
                status=status_state,
                confidence="SUSPECTED" if status_state == FindingLifecycleState.INCONCLUSIVE.value else "OBSERVED",
                evidence_level="E0",
                vulnerability_type="auth_bypass",
                adapter_name="AuthBypassValidator",
                title="Public Page or Login Form (Not an Auth Bypass)",
                severity="INFO",
                target_host=finding_context.get("target_host", ""),
                endpoint_url=target_url,
                actual_result="The requested endpoint is a public login page or landing route legitimately returning HTTP 200.",
                expected_result="Protected private resource returning HTTP 401/403 baseline and bypassed via header/path manipulation.",
            )

        return NormalizedValidationResult(
            status=FindingLifecycleState.CONFIRMED.value,
            confidence="CONFIRMED",
            evidence_level="E4",
            vulnerability_type="auth_bypass",
            adapter_name="AuthBypassValidator",
            title="Authentication Bypass on Protected Resource",
            severity="CRITICAL",
            target_host=finding_context.get("target_host", ""),
            endpoint_url=target_url,
            cwe_id="CWE-287",
            actual_result=f"Protected functional route accessed without authentication using '{bypass_header_used}'.",
            expected_result="Enforce centralized session/token verification on all non-public routes.",
            remediation="Ensure authentication middleware verifies cryptographically signed session cookies or JWT tokens, ignoring untrusted reverse-proxy headers.",
            poc_command=f"curl -s -k -H '{bypass_header_used}' '{target_url}'",
        )

    def evaluate_evidence(self, evidence_pkg: TypedEvidencePackage) -> Tuple[bool, str, int]:
        diff = evidence_pkg.differential
        if not diff or not diff.behavioral_anomaly_confirmed:
            return False, FindingLifecycleState.REJECTED.value, 10
        return True, FindingLifecycleState.CONFIRMED.value, 96


auth_bypass_validator = AuthBypassValidator()
