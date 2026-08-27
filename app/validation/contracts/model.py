"""Vulnerability Contract Schema & Model (V10 Evidence-Driven Validation Architecture).

Defines the formal technical contract that every vulnerability class must fulfill
before any finding can be elevated to VALIDATED or CONFIRMED.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class SafeValidationLevel(str, Enum):
    PASSIVE = "PASSIVE"
    NON_DESTRUCTIVE_BENIGN = "NON_DESTRUCTIVE_BENIGN"
    CONTROLLED_MUTATION = "CONTROLLED_MUTATION"
    DIFFERENTIAL_PROBE = "DIFFERENTIAL_PROBE"
    REQUIRES_EXPLICIT_AUTHORIZATION = "REQUIRES_EXPLICIT_AUTHORIZATION"


@dataclass
class VulnerabilityContract:
    """Formal verification contract for a specific vulnerability class."""
    id: str  # e.g., "sqli", "xss", "slowloris", "rce", "idor"
    name: str
    category: str  # "injection", "authorization", "denial_of_service", "crypto", etc.
    cwe_id: str
    detection_strategy: str
    validation_strategy: str
    required_evidence: List[str] = field(default_factory=list)
    supporting_evidence: List[str] = field(default_factory=list)
    confirmation_rules: List[str] = field(default_factory=list)
    rejection_rules: List[str] = field(default_factory=list)
    confidence_model: Dict[str, Any] = field(default_factory=dict)
    safe_validation_level: SafeValidationLevel = SafeValidationLevel.NON_DESTRUCTIVE_BENIGN
    requires_baseline: bool = True
    requires_control_comparison: bool = True
    allows_status_code_only_confirmation: bool = False  # MUST ALWAYS BE FALSE

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "cwe_id": self.cwe_id,
            "detection_strategy": self.detection_strategy,
            "validation_strategy": self.validation_strategy,
            "required_evidence": self.required_evidence,
            "supporting_evidence": self.supporting_evidence,
            "confirmation_rules": self.confirmation_rules,
            "rejection_rules": self.rejection_rules,
            "confidence_model": self.confidence_model,
            "safe_validation_level": self.safe_validation_level.value,
            "requires_baseline": self.requires_baseline,
            "requires_control_comparison": self.requires_control_comparison,
            "allows_status_code_only_confirmation": self.allows_status_code_only_confirmation,
        }
