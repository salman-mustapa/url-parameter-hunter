"""Arbitrary File Upload Vulnerability-Specific Validator (V10 Architecture).

Strict Principles:
1. Upload form returning HTTP 200 is NOT RCE.
2. Storing uploaded file as static octet-stream / plain text is NOT code execution.
3. Requires multi-stage proof: Upload Accepted -> File Stored -> Code Executed via Benign Canary.
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

logger = logging.getLogger("validation.validators.file_upload")


class FileUploadValidator(BaseVulnerabilityValidator):
    """Validator evaluating Arbitrary File Upload & Server-Side Execution."""

    def __init__(self) -> None:
        super().__init__("file_upload")

    async def validate(
        self,
        target_url: str,
        finding_context: Dict[str, Any],
        session_context: Any,
    ) -> NormalizedValidationResult:
        raw_evidence = finding_context.get("raw_evidence", {}) or {}

        upload_accepted = bool(raw_evidence.get("upload_accepted", False))
        file_stored_url = str(raw_evidence.get("file_stored_url", ""))
        canary_executed = bool(raw_evidence.get("canary_script_executed", False))
        canary_output = str(raw_evidence.get("canary_output", ""))

        # Stage separation
        is_rce_proven = upload_accepted and bool(file_stored_url) and canary_executed

        pkg = TypedEvidencePackage(
            finding_id=finding_context.get("id", "upload_test"),
            vulnerability_type="file_upload",
            target_url=target_url,
            contract_id="file_upload",
            differential=DifferentialObservation(
                baseline_request={"url": target_url},
                baseline_response={"status_code": 200},
                test_request={"upload": "canary.phtml"},
                test_response={"accepted": upload_accepted, "stored": file_stored_url, "executed": canary_executed},
                differences=["Script uploaded and executed server-side" if is_rce_proven else "Upload only (no execution)"],
                significance_score=1.0 if is_rce_proven else (0.4 if upload_accepted else 0.0),
                behavioral_anomaly_confirmed=is_rce_proven,
            ),
        )

        if is_rce_proven:
            pkg.items.append(
                TypedEvidenceItem(
                    evidence_type=EvidenceType.COMMAND_EXECUTION,
                    title="Uploaded Script Server-Side Execution Verified",
                    description=f"Canary script at '{file_stored_url}' executed and returned hash: {canary_output}",
                    data={"url": file_stored_url, "output": canary_output},
                    is_primary_proof=True,
                )
            )

        is_confirmed, status_state, conf_score = self.evaluate_evidence(pkg)

        if not is_confirmed:
            return NormalizedValidationResult(
                status=status_state,
                confidence="SUSPECTED" if status_state == FindingLifecycleState.INCONCLUSIVE.value else "OBSERVED",
                evidence_level="E1" if upload_accepted else "E0",
                vulnerability_type="file_upload",
                adapter_name="FileUploadValidator",
                title="File Upload Endpoint (No Code Execution Proven)",
                severity="LOW" if upload_accepted else "INFO",
                target_host=finding_context.get("target_host", ""),
                endpoint_url=target_url,
                actual_result="File upload accepted or stored statically, but script execution was blocked or not demonstrable.",
                expected_result="Multi-stage verification: Upload Accepted -> File Accessible -> Server Executes Script.",
            )

        return NormalizedValidationResult(
            status=FindingLifecycleState.CONFIRMED.value,
            confidence="CONFIRMED",
            evidence_level="E4",
            vulnerability_type="file_upload",
            adapter_name="FileUploadValidator",
            title="Arbitrary File Upload Leading to Remote Code Execution",
            severity="CRITICAL",
            target_host=finding_context.get("target_host", ""),
            endpoint_url=target_url,
            cwe_id="CWE-434",
            actual_result=f"Uploaded script at '{file_stored_url}' executed by server, returning canary token '{canary_output}'.",
            expected_result="Strict extension whitelisting, randomized non-executable storage outside webroot, and disabling script execution in upload directory.",
            remediation="Store uploads outside webroot or in object storage with Content-Disposition: attachment, enforcing MIME and extension whitelists.",
            poc_command=f"curl -s -k '{file_stored_url}'",
        )

    def evaluate_evidence(self, evidence_pkg: TypedEvidencePackage) -> Tuple[bool, str, int]:
        diff = evidence_pkg.differential
        if not diff or not diff.behavioral_anomaly_confirmed:
            return False, FindingLifecycleState.INCONCLUSIVE.value, 40
        return True, FindingLifecycleState.CONFIRMED.value, 98


file_upload_validator = FileUploadValidator()
