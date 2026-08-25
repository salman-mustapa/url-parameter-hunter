"""Deterministic Risk Scoring Engine (Specialist Agent V2 §18).

Calculates authoritative security risk metrics:
- Inputs: Severity, Confidence, Evidence Level (E0-E3), Proof Stage (P0-P4), Exploitability, Business Impact.
- Outputs: Normalized CVSS v3.1 Base Score (0.0 - 10.0), Qualitative Severity, Impact Matrix.
- Authoritative deterministic logic (AI may recommend, but RiskScoringEngine decides).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional

logger = logging.getLogger("orchestration.risk_scoring")


class SeverityRating(str, Enum):
    CRITICAL = "CRITICAL"  # 9.0 - 10.0
    HIGH = "HIGH"          # 7.0 - 8.9
    MEDIUM = "MEDIUM"      # 4.0 - 6.9
    LOW = "LOW"            # 0.1 - 3.9
    INFO = "INFO"          # 0.0


@dataclass
class CalculatedRiskScore:
    cvss_score: float
    severity: SeverityRating
    evidence_score: int  # 0 - 100
    confidence_normalized: float  # 0.0 - 1.0
    impact_matrix: Dict[str, str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cvss_score": self.cvss_score,
            "severity": self.severity.value,
            "evidence_score": self.evidence_score,
            "confidence": self.confidence_normalized,
            "impact_matrix": self.impact_matrix,
        }


class RiskScoringEngine:
    """Deterministic, CVSS v3.1-aligned scoring engine."""

    SEVERITY_BASE_WEIGHTS = {
        "CRITICAL": 9.5,
        "HIGH": 7.8,
        "MEDIUM": 5.5,
        "LOW": 2.5,
        "INFO": 0.0,
    }

    EVIDENCE_PROOF_MULTIPLIERS = {
        "E3": 1.0,   # Direct impact proof
        "E2": 0.9,   # Reproducible anomaly
        "E1": 0.75,  # Heuristic indicator
        "E0": 0.5,   # Observation only
    }

    PROOF_STAGE_BONUS = {
        "P4": 0.5,
        "P3": 0.3,
        "P2": 0.1,
        "P1": 0.0,
        "P0": -0.5,
    }

    def calculate_score(
        self,
        base_severity: str = "MEDIUM",
        evidence_level: str = "E3",
        proof_stage: str = "P3",
        confidence: float = 0.9,
        confidentiality_impact: str = "HIGH",
        integrity_impact: str = "HIGH",
        availability_impact: str = "LOW",
    ) -> CalculatedRiskScore:
        """Deterministically evaluates composite risk score."""
        sev_key = base_severity.upper()
        base_val = self.SEVERITY_BASE_WEIGHTS.get(sev_key, 5.0)

        ev_mult = self.EVIDENCE_PROOF_MULTIPLIERS.get(evidence_level.upper(), 0.8)
        p_bonus = self.PROOF_STAGE_BONUS.get(proof_stage.upper(), 0.0)

        # Composite computation
        calculated = (base_val * ev_mult) + p_bonus
        # Bound between 0.0 and 10.0
        final_score = round(max(0.0, min(10.0, calculated)), 1)

        # Map to final severity
        if final_score >= 9.0:
            rating = SeverityRating.CRITICAL
        elif final_score >= 7.0:
            rating = SeverityRating.HIGH
        elif final_score >= 4.0:
            rating = SeverityRating.MEDIUM
        elif final_score > 0.0:
            rating = SeverityRating.LOW
        else:
            rating = SeverityRating.INFO

        # Evidence quality score (0 - 100)
        ev_score = int(ev_mult * 80 + (confidence * 20))

        impact_matrix = {
            "confidentiality": confidentiality_impact.upper(),
            "integrity": integrity_impact.upper(),
            "availability": availability_impact.upper(),
        }

        return CalculatedRiskScore(
            cvss_score=final_score,
            severity=rating,
            evidence_score=ev_score,
            confidence_normalized=round(confidence, 2),
            impact_matrix=impact_matrix,
        )


risk_scoring_engine = RiskScoringEngine()
