"""11-State Finding Lifecycle State Machine & Confidence Engine (V10 Architecture).

Implements strict lifecycle state transitions, quality checks, and confidence scoring.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

logger = logging.getLogger("validation.state_machine")


class FindingLifecycleState(str, Enum):
    # Active lifecycle progression
    DISCOVERED = "DISCOVERED"
    TRIAGED = "TRIAGED"
    CANDIDATE = "CANDIDATE"
    VALIDATING = "VALIDATING"
    VALIDATED = "VALIDATED"
    CONFIRMED = "CONFIRMED"
    REPORTED = "REPORTED"

    # Terminal / Non-vulnerable / Failure states
    REJECTED = "REJECTED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    INCONCLUSIVE = "INCONCLUSIVE"
    UNSAFE_TO_VALIDATE = "UNSAFE_TO_VALIDATE"


_PROGRESSION = {
    "DISCOVERED": {"TRIAGED", "CANDIDATE", "VALIDATING"},
    "TRIAGED": {"CANDIDATE", "VALIDATING"},
    "CANDIDATE": {"VALIDATING"},
    "VALIDATING": {"VALIDATED"},
    "VALIDATED": {"CONFIRMED", "VALIDATING"},
    "CONFIRMED": {"REPORTED", "VALIDATING"},
    "REPORTED": {"VALIDATING"},
    "INCONCLUSIVE": {"VALIDATING"},
    "REJECTED": {"VALIDATING"},
    "FALSE_POSITIVE": {"VALIDATING"},
    "UNSAFE_TO_VALIDATE": {"VALIDATING"},
}
_NEGATIVE = {"REJECTED", "FALSE_POSITIVE", "INCONCLUSIVE", "UNSAFE_TO_VALIDATE"}


class ConfidenceRating(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"  # 0-20
    WEAK_SIGNAL = "WEAK_SIGNAL"  # 21-40
    SUSPECTED = "SUSPECTED"  # 41-60
    PROBABLE = "PROBABLE"  # 61-75
    VALIDATED = "VALIDATED"  # 76-90
    CONFIRMED = "CONFIRMED"  # 91-100


@dataclass
class FindingLifecycleRecord:
    """Tracks state progression, timestamps, and quality gate transitions for a finding."""

    finding_id: str
    current_state: FindingLifecycleState = FindingLifecycleState.DISCOVERED
    confidence_rating: ConfidenceRating = ConfidenceRating.INFORMATIONAL
    confidence_score: int = 10
    history: list[dict[str, Any]] = field(default_factory=list)
    state_reason: str = "Initial observation"
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    evidence_ids: list[str] = field(default_factory=list)

    def transition_to(
        self,
        new_state: FindingLifecycleState,
        reason: str,
        confidence_score: int | None = None,
        evidence_ids: list[str] | None = None,
    ) -> bool:
        """Transitions finding to a new lifecycle state with validation checks."""
        old_state = self.current_state
        new_state = FindingLifecycleState(new_state)
        allowed = _PROGRESSION.get(old_state.value, set()) | _NEGATIVE
        if new_state.value not in allowed:
            raise ValueError(f"Invalid finding transition: {old_state.value} -> {new_state.value}")
        if new_state in {FindingLifecycleState.VALIDATED, FindingLifecycleState.CONFIRMED}:
            if not (evidence_ids or self.evidence_ids):
                raise ValueError("Validated/confirmed findings require evidence references")
        if evidence_ids:
            self.evidence_ids = list(dict.fromkeys(evidence_ids))
        self.history.append(
            {
                "from_state": old_state.value,
                "to_state": new_state.value,
                "reason": reason,
                "timestamp": datetime.now(UTC).isoformat(),
            }
        )
        self.current_state = new_state
        self.state_reason = reason
        self.updated_at = datetime.now(UTC).isoformat()

        if confidence_score is not None:
            self.set_confidence(confidence_score)

        logger.debug(
            "Finding %s transitioned: %s -> %s (Reason: %s)",
            self.finding_id,
            old_state.value,
            new_state.value,
            reason,
        )
        return True

    def set_confidence(self, score: int) -> None:
        """Calculates confidence tier from raw 0-100 score."""
        self.confidence_score = max(0, min(100, score))
        if self.confidence_score <= 20:
            self.confidence_rating = ConfidenceRating.INFORMATIONAL
        elif self.confidence_score <= 40:
            self.confidence_rating = ConfidenceRating.WEAK_SIGNAL
        elif self.confidence_score <= 60:
            self.confidence_rating = ConfidenceRating.SUSPECTED
        elif self.confidence_score <= 75:
            self.confidence_rating = ConfidenceRating.PROBABLE
        elif self.confidence_score <= 90:
            self.confidence_rating = ConfidenceRating.VALIDATED
        else:
            self.confidence_rating = ConfidenceRating.CONFIRMED

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "current_state": self.current_state.value,
            "confidence_rating": self.confidence_rating.value,
            "confidence_score": self.confidence_score,
            "state_reason": self.state_reason,
            "history": self.history,
            "updated_at": self.updated_at,
            "evidence_ids": list(self.evidence_ids),
        }


@dataclass
class Finding(FindingLifecycleRecord):
    """Validation-domain finding; persisted in the existing SQLAlchemy Finding model."""

    vulnerability_type: str = ""
    asset: str = ""
