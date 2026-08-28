"""Normalized Validation Result Schema (V5 §39).
Defines standard output contract returned by all Deep Validation Adapters.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class NormalizedValidationResult:
    """Standardized validation payload produced by validation adapters (§39)."""

    status: str = (
        "CANDIDATE"  # DISCOVERED, CANDIDATE, VALIDATED, CONFIRMED, FALSE_POSITIVE, INCONCLUSIVE
    )
    confidence: str = "OBSERVED"  # OBSERVED, SUSPECTED, VALIDATED, CONFIRMED
    evidence_level: str = "E0"  # E0, E1, E2, E3, E4 (§2)
    evidence_score: int = 10  # 0-100 (§26)
    vulnerability_type: str = "generic"
    adapter_name: str = "generic_adapter"
    title: str = ""
    severity: str = "INFO"  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    target_host: str = ""
    endpoint_url: str = ""
    parameter: str | None = None
    location: str | None = None  # query, body, header, path
    cwe_id: str | None = None
    cve_id: str | None = None
    cvss_score: float | None = None
    description: str | None = None
    impact_matrix: dict[str, Any] = field(default_factory=dict)
    root_cause: str | None = None
    preconditions: list[str] = field(default_factory=list)
    reproduction_steps: list[str] = field(default_factory=list)
    expected_result: str | None = None
    actual_result: str | None = None
    executive_explanation: str | None = None
    business_impact: str | None = None
    remediation: str | None = None
    poc_command: str | None = None
    poc_payload: str | None = None
    request_metadata: dict[str, Any] = field(default_factory=dict)
    response_metadata: dict[str, Any] = field(default_factory=dict)
    exploitation_data: dict[str, Any] = field(
        default_factory=dict
    )  # Deep exploitation evidence (DB schemas, file contents, etc.)
    observations: list[dict[str, Any]] = field(default_factory=list)
    screenshots: list[dict[str, Any]] = field(default_factory=list)
    cleanup_status: str = "COMPLETED"
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    evidence: list[dict[str, Any]] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    validation_proof: Any = field(default=None, repr=False)
    false_positive_checks: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        from app.reporting.redaction import RedactionEngine

        data = {name: value for name, value in self.__dict__.items() if name != "validation_proof"}
        return RedactionEngine.redact_dict(data)

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


ValidationResult = NormalizedValidationResult
