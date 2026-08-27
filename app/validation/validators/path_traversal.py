"""Path Traversal / LFI Vulnerability-Specific Validator (V10 Architecture).

Strict Principles:
1. HTTP 200 alone is NOT Path Traversal proof.
2. Normalized traversal or generic response is NOT Path Traversal.
3. Requires structured file content signature (e.g. root:x:0:0 or [fonts]).
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

logger = logging.getLogger("validation.validators.path_traversal")

CANONICAL_FILE_PATTERNS = [
    re.compile(r"root:[x*]:0:0:", re.I),
    re.compile(r"\[(fonts|extensions|boot loader)\]", re.I),
    re.compile(r"<\?php", re.I),
    re.compile(r"APP_KEY=base64:", re.I),
    re.compile(r"DB_PASSWORD=", re.I),
]


class PathTraversalValidator(BaseVulnerabilityValidator):
    """Validator evaluating Path Traversal / Local File Inclusion."""

    def __init__(self) -> None:
        super().__init__("path_traversal")

    async def validate(
        self,
        target_url: str,
        finding_context: Dict[str, Any],
        session_context: Any,
    ) -> NormalizedValidationResult:
        param = finding_context.get("parameter", "file")
        raw_evidence = finding_context.get("raw_evidence", {}) or {}

        body = str(raw_evidence.get("response_body", ""))
        status_code = int(raw_evidence.get("status_code", 200))

        has_file_content = any(p.search(body) for p in CANONICAL_FILE_PATTERNS)

        pkg = TypedEvidencePackage(
            finding_id=finding_context.get("id", "traversal_test"),
            vulnerability_type="path_traversal",
            target_url=target_url,
            contract_id="path_traversal",
            differential=DifferentialObservation(
                baseline_request={"url": target_url},
                baseline_response={"status_code": 200},
                test_request={"param": param, "payload": "../../../../etc/passwd"},
                test_response={"status_code": status_code, "has_file_content": has_file_content},
                differences=["Canonical system file contents disclosed" if has_file_content else "No file contents disclosed"],
                significance_score=1.0 if has_file_content else 0.0,
                behavioral_anomaly_confirmed=has_file_content,
            ),
        )

        if has_file_content:
            pkg.items.append(
                TypedEvidenceItem(
                    evidence_type=EvidenceType.RESOURCE_ACCESS,
                    title="Unauthorized System File Content Disclosed",
                    description="Response body matches canonical system file regular expression pattern.",
                    data={"matched_snippet": body[:200]},
                    is_primary_proof=True,
                )
            )

        is_confirmed, status_state, conf_score = self.evaluate_evidence(pkg)

        if not is_confirmed:
            return NormalizedValidationResult(
                status=status_state,
                confidence="SUSPECTED" if status_state == FindingLifecycleState.INCONCLUSIVE.value else "OBSERVED",
                evidence_level="E0",
                vulnerability_type="path_traversal",
                adapter_name="PathTraversalValidator",
                title=f"Path Traversal Probe on '{param}' (Unconfirmed)",
                severity="INFO",
                target_host=finding_context.get("target_host", ""),
                endpoint_url=target_url,
                parameter=param,
                actual_result="Server returned HTTP 200 or normalized path without disclosing unauthorized file contents.",
                expected_result="Disclosure of canonical system file content matching known structural signatures.",
            )

        return NormalizedValidationResult(
            status=FindingLifecycleState.CONFIRMED.value,
            confidence="CONFIRMED",
            evidence_level="E3",
            vulnerability_type="path_traversal",
            adapter_name="PathTraversalValidator",
            title=f"Path Traversal / Local File Inclusion on '{param}'",
            severity="HIGH",
            target_host=finding_context.get("target_host", ""),
            endpoint_url=target_url,
            parameter=param,
            cwe_id="CWE-22",
            actual_result="Unauthorized file contents retrieved via directory traversal sequence.",
            expected_result="Strict path normalization, basename resolution, or strict file whitelist.",
            remediation="Use basename() or resolve paths against a safe root directory, rejecting ../ sequences.",
            poc_command=f"curl -s -k '{target_url}?{param}=../../../../etc/passwd'",
        )

    def evaluate_evidence(self, evidence_pkg: TypedEvidencePackage) -> Tuple[bool, str, int]:
        diff = evidence_pkg.differential
        if not diff or not diff.behavioral_anomaly_confirmed:
            return False, FindingLifecycleState.REJECTED.value, 15
        return True, FindingLifecycleState.CONFIRMED.value, 95


path_traversal_validator = PathTraversalValidator()
