"""Base Vulnerability Validator (V10 Evidence-Driven Validation Architecture).

Abstract base class establishing mandatory methods:
- validate()
- evaluate_evidence()
- calculate_confidence()
- run_differential_test()
"""

from __future__ import annotations

import abc
import hashlib
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

from app.validation.contracts.model import VulnerabilityContract
from app.validation.contracts.registry import contract_registry
from app.validation.evidence.typed_evidence import (
    DifferentialObservation,
    EvidenceType,
    TypedEvidenceItem,
    TypedEvidencePackage,
)
from app.validation.result import NormalizedValidationResult
from app.validation.safety.engine import safety_engine
from app.validation.state_machine import FindingLifecycleState

logger = logging.getLogger("validation.validators.base")


class BaseVulnerabilityValidator(abc.ABC):
    """Abstract base class for all vulnerability-specific differential validators."""

    def __init__(self, vulnerability_type: str) -> None:
        self.vulnerability_type = vulnerability_type
        self.contract: Optional[VulnerabilityContract] = contract_registry.get(vulnerability_type)
        if not self.contract:
            logger.warning("No formal contract found in registry for vulnerability type: %s", vulnerability_type)

    @abc.abstractmethod
    async def validate(
        self,
        target_url: str,
        finding_context: Dict[str, Any],
        session_context: Any,
    ) -> NormalizedValidationResult:
        """Executes vulnerability-specific validation flow."""
        raise NotImplementedError

    @abc.abstractmethod
    def evaluate_evidence(
        self,
        evidence_pkg: TypedEvidencePackage,
    ) -> Tuple[bool, str, int]:
        """Evaluates whether technical evidence fulfills contract rules.
        Returns: (is_confirmed, status_state, confidence_score)
        """
        raise NotImplementedError

    def calculate_confidence(self, evidence_pkg: TypedEvidencePackage) -> int:
        """Computes confidence score based on contract required/supporting evidence match."""
        if not self.contract:
            return 50

        score = 20  # Base observation score
        evidence_types_present = {item.evidence_type.value for item in evidence_pkg.items}

        if evidence_pkg.differential and evidence_pkg.differential.behavioral_anomaly_confirmed:
            score += 35

        if len(evidence_pkg.items) >= 2:
            score += 15

        if evidence_pkg.reproduction_command:
            score += 15

        # Check contract requirements
        req_met = True
        for req in self.contract.required_evidence:
            # Check if any item title/description or differential matches requirement
            if not any(req.lower() in item.title.lower() or req.lower() in item.description.lower() for item in evidence_pkg.items):
                if not (req.lower().startswith("baseline") and evidence_pkg.differential and evidence_pkg.differential.baseline_response):
                    req_met = False

        if not req_met:
            score = min(score, 50)  # Cap score if mandatory evidence is missing

        return min(100, score)

    def create_empty_result(
        self,
        target_url: str,
        finding_context: Dict[str, Any],
        status: str = FindingLifecycleState.INCONCLUSIVE.value,
        confidence: str = "SUSPECTED",
        reason: str = "Insufficient evidence",
    ) -> NormalizedValidationResult:
        """Creates a standardized default/inconclusive validation result."""
        return NormalizedValidationResult(
            status=status,
            confidence=confidence,
            evidence_level="E0",
            vulnerability_type=self.vulnerability_type,
            adapter_name=self.__class__.__name__,
            title=finding_context.get("title", f"Potential {self.vulnerability_type.upper()}"),
            severity=finding_context.get("severity", "INFO"),
            target_host=finding_context.get("target_host", ""),
            endpoint_url=target_url,
            parameter=finding_context.get("parameter"),
            actual_result=reason,
            expected_result="Evidence proves vulnerability mechanism according to technical contract.",
        )
