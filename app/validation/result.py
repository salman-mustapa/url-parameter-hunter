"""Normalized Validation Result Schema (V5 §39).
Defines standard output contract returned by all Deep Validation Adapters.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class NormalizedValidationResult:
    """Standardized validation payload produced by validation adapters (§39)."""
    status: str = "CANDIDATE"  # DISCOVERED, CANDIDATE, VALIDATED, CONFIRMED, FALSE_POSITIVE, INCONCLUSIVE
    confidence: str = "OBSERVED"  # OBSERVED, SUSPECTED, VALIDATED, CONFIRMED
    evidence_level: str = "E0"  # E0, E1, E2, E3, E4 (§2)
    evidence_score: int = 10  # 0-100 (§26)
    vulnerability_type: str = "generic"
    adapter_name: str = "generic_adapter"
    title: str = ""
    severity: str = "INFO"  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    target_host: str = ""
    endpoint_url: str = ""
    parameter: Optional[str] = None
    location: Optional[str] = None  # query, body, header, path
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    description: Optional[str] = None
    impact_matrix: Dict[str, Any] = field(default_factory=dict)
    root_cause: Optional[str] = None
    preconditions: List[str] = field(default_factory=list)
    reproduction_steps: List[str] = field(default_factory=list)
    expected_result: Optional[str] = None
    actual_result: Optional[str] = None
    executive_explanation: Optional[str] = None
    business_impact: Optional[str] = None
    remediation: Optional[str] = None
    poc_command: Optional[str] = None
    poc_payload: Optional[str] = None
    request_metadata: Dict[str, Any] = field(default_factory=dict)
    response_metadata: Dict[str, Any] = field(default_factory=dict)
    observations: List[Dict[str, Any]] = field(default_factory=list)
    screenshots: List[Dict[str, Any]] = field(default_factory=list)
    cleanup_status: str = "COMPLETED"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def calculate_evidence_score(self) -> int:
        """Calculate evidence score using V5 §26 formula.

        Base scores by evidence level:
            E0 (Observation): 10
            E1 (Technical indicator): 30
            E2 (Reproducible): 55
            E3 (Impact proof): 75
            E4 (Full exploitation proof): 90

        Bonuses:
            +10 corroboration (multiple observations)
            +5  screenshot attached
            +10 controlled reproduction steps present
            +5  impact matrix populated
            +5  PoC command/payload present

        Cap at 100.
        """
        base_scores = {"E0": 10, "E1": 30, "E2": 55, "E3": 75, "E4": 90}
        score = base_scores.get(self.evidence_level, 10)

        # Corroboration bonus
        if len(self.observations) > 1:
            score += 10

        # Screenshot bonus
        if self.screenshots:
            score += 5

        # Reproduction steps bonus
        if self.reproduction_steps and len(self.reproduction_steps) >= 2:
            score += 10

        # Impact matrix bonus
        if self.impact_matrix and len(self.impact_matrix) >= 3:
            score += 5

        # PoC command/payload bonus
        if self.poc_command or self.poc_payload:
            score += 5

        self.evidence_score = min(score, 100)
        return self.evidence_score

    def needs_validation(self) -> bool:
        """Check if this result is High-Severity but Low-Confidence (V4 §90).

        Returns True when finding needs additional validation before
        being treated as confirmed.
        """
        high_severity = self.severity in ("HIGH", "CRITICAL")
        low_confidence = self.confidence in ("OBSERVED", "SUSPECTED")
        return high_severity and low_confidence

