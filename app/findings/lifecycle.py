"""Finding Lifecycle & Exploitability State Machine (V8 §20, §21, §26, §27 & V9.1 §2, §19).

Four-Axis Separation (V9.1 §19):
1. Severity: CRITICAL, HIGH, MEDIUM, LOW, INFO
2. Confidence: OBSERVED, SUSPECTED, VALIDATED, CONFIRMED
3. Evidence Level: E0, E1, E2, E3, E4
4. Exploitability State:
   - NOT_MATCHED
   - CANDIDATE
   - NOT_APPLICABLE
   - BLOCKED
   - READY
   - BASELINE_CAPTURED
   - CONTROLLED_TEST
   - RESPONSE_COMPARISON
   - SECURITY_BEHAVIOR_CONFIRMED
   - IMPACT_PROOF
   - INSUFFICIENT
   - VALIDATED
   - EVIDENCE_QUALITY_GATE
   - CONFIRMED
   - NOT_EXPLOITABLE
   - PATCHED
   - INCONCLUSIVE

Validation State Machine Flow (V9.1 §2):
OBSERVED -> CANDIDATE -> PRECONDITION_CHECK (NOT_APPLICABLE / BLOCKED / READY)
-> BASELINE_CAPTURED -> CONTROLLED_TEST -> RESPONSE_COMPARISON
-> SECURITY_BEHAVIOR_CONFIRMED -> IMPACT_PROOF (INSUFFICIENT / SUFFICIENT)
-> EVIDENCE_QUALITY_GATE -> CONFIRMED -> REPORTED -> RETEST -> RETESTING -> FIXED/NOT_FIXED
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


class ExploitabilityState:
    NOT_MATCHED = "NOT_MATCHED"
    CANDIDATE = "CANDIDATE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    BLOCKED = "BLOCKED"
    READY = "READY"
    BASELINE_CAPTURED = "BASELINE_CAPTURED"
    CONTROLLED_TEST = "CONTROLLED_TEST"
    RESPONSE_COMPARISON = "RESPONSE_COMPARISON"
    SECURITY_BEHAVIOR_CONFIRMED = "SECURITY_BEHAVIOR_CONFIRMED"
    IMPACT_PROOF = "IMPACT_PROOF"
    INSUFFICIENT = "INSUFFICIENT"
    APPLICABLE = "APPLICABLE"
    VALIDATION_PENDING = "VALIDATION_PENDING"
    VALIDATING = "VALIDATING"
    VALIDATED = "VALIDATED"
    EVIDENCE_QUALITY_GATE = "EVIDENCE_QUALITY_GATE"
    CONFIRMED = "CONFIRMED"
    NOT_EXPLOITABLE = "NOT_EXPLOITABLE"
    PATCHED = "PATCHED"
    INCONCLUSIVE = "INCONCLUSIVE"

    ALL_STATES = [
        NOT_MATCHED,
        CANDIDATE,
        NOT_APPLICABLE,
        BLOCKED,
        READY,
        BASELINE_CAPTURED,
        CONTROLLED_TEST,
        RESPONSE_COMPARISON,
        SECURITY_BEHAVIOR_CONFIRMED,
        IMPACT_PROOF,
        INSUFFICIENT,
        APPLICABLE,
        VALIDATION_PENDING,
        VALIDATING,
        VALIDATED,
        EVIDENCE_QUALITY_GATE,
        CONFIRMED,
        NOT_EXPLOITABLE,
        PATCHED,
        INCONCLUSIVE,
    ]


@dataclass
class FindingQualityProfile:
    """Four-axis quality and status model (V9.1 §19)."""
    severity: str = "MEDIUM"  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence: str = "SUSPECTED"  # OBSERVED, SUSPECTED, VALIDATED, CONFIRMED
    evidence_level: str = "E1"  # E0, E1, E2, E3, E4
    exploitability: str = ExploitabilityState.CANDIDATE
    poc_valid: bool = False
    report_ready: bool = False
    details: Dict[str, Any] = field(default_factory=dict)

    def is_defensible_confirmed(self) -> bool:
        """Determines if finding satisfies all criteria for confirmed reporting."""
        return (
            self.confidence == "CONFIRMED"
            and self.evidence_level in ("E2", "E3", "E4")
            and self.exploitability == ExploitabilityState.CONFIRMED
            and self.poc_valid is True
        )


class FindingLifecycle:
    """Finding Lifecycle & Validation State Machine (V8 §21, V9.1 §2)."""

    STATES = {
        "OPEN",
        "DISCOVERED",
        "OBSERVED",
        "CANDIDATE",
        "PRECONDITION_CHECK",
        "NOT_APPLICABLE",
        "BLOCKED",
        "READY",
        "BASELINE_CAPTURED",
        "CONTROLLED_TEST",
        "RESPONSE_COMPARISON",
        "SECURITY_BEHAVIOR_CONFIRMED",
        "TRIAGED",
        "APPLICABILITY_CHECK",
        "VALIDATION_PENDING",
        "VALIDATING",
        "INCONCLUSIVE",
        "FALSE_POSITIVE",
        "VALIDATED",
        "IMPACT_PROOF",
        "INSUFFICIENT",
        "EVIDENCE_QUALITY_GATE",
        "CONFIRMED",
        "REPORTED",
        "RETEST",
        "RETESTING",
        "FIXED",
        "NOT_FIXED",
        "REOPENED",
        "ACCEPTED_RISK",
        "CLOSED",
    }

    VALID_TRANSITIONS: Dict[str, Set[str]] = {
        "OPEN": {"TRIAGED", "FALSE_POSITIVE", "CLOSED", "ACCEPTED_RISK"},
        "DISCOVERED": {"OBSERVED", "CANDIDATE", "PRECONDITION_CHECK", "TRIAGED", "FALSE_POSITIVE", "CLOSED"},
        "OBSERVED": {"CANDIDATE", "PRECONDITION_CHECK", "FALSE_POSITIVE", "CLOSED"},
        "CANDIDATE": {
            "PRECONDITION_CHECK",
            "TRIAGED",
            "APPLICABILITY_CHECK",
            "READY",
            "VALIDATING",
            "VALIDATION_PENDING",
            "NOT_APPLICABLE",
            "BLOCKED",
            "FALSE_POSITIVE",
            "CLOSED",
        },
        "PRECONDITION_CHECK": {
            "NOT_APPLICABLE",
            "BLOCKED",
            "READY",
            "CANDIDATE",
            "FALSE_POSITIVE",
        },
        "NOT_APPLICABLE": {"REOPENED", "CLOSED"},
        "BLOCKED": {"PRECONDITION_CHECK", "REOPENED", "CLOSED"},
        "READY": {"BASELINE_CAPTURED", "CONTROLLED_TEST", "VALIDATING", "FALSE_POSITIVE", "BLOCKED"},
        "BASELINE_CAPTURED": {"CONTROLLED_TEST", "VALIDATING", "INCONCLUSIVE", "FALSE_POSITIVE"},
        "CONTROLLED_TEST": {"RESPONSE_COMPARISON", "VALIDATING", "INCONCLUSIVE", "FALSE_POSITIVE"},
        "RESPONSE_COMPARISON": {
            "SECURITY_BEHAVIOR_CONFIRMED",
            "INCONCLUSIVE",
            "FALSE_POSITIVE",
            "NOT_EXPLOITABLE",
        },
        "SECURITY_BEHAVIOR_CONFIRMED": {
            "IMPACT_PROOF",
            "VALIDATED",
            "EVIDENCE_QUALITY_GATE",
            "INSUFFICIENT",
        },
        "TRIAGED": {"APPLICABILITY_CHECK", "PRECONDITION_CHECK", "VALIDATION_PENDING", "VALIDATING", "FALSE_POSITIVE", "CLOSED"},
        "APPLICABILITY_CHECK": {"VALIDATION_PENDING", "READY", "VALIDATING", "INCONCLUSIVE", "FALSE_POSITIVE", "NOT_EXPLOITABLE"},
        "VALIDATION_PENDING": {"VALIDATING", "READY", "BASELINE_CAPTURED", "INCONCLUSIVE", "FALSE_POSITIVE"},
        "VALIDATING": {
            "RESPONSE_COMPARISON",
            "SECURITY_BEHAVIOR_CONFIRMED",
            "VALIDATED",
            "IMPACT_PROOF",
            "EVIDENCE_QUALITY_GATE",
            "CONFIRMED",
            "INCONCLUSIVE",
            "FALSE_POSITIVE",
            "CANDIDATE",
            "NOT_EXPLOITABLE",
        },
        "INCONCLUSIVE": {"PRECONDITION_CHECK", "VALIDATION_PENDING", "VALIDATING", "CLOSED", "REOPENED"},
        "VALIDATED": {"IMPACT_PROOF", "EVIDENCE_QUALITY_GATE", "CONFIRMED", "FIXED", "ACCEPTED_RISK", "FALSE_POSITIVE"},
        "IMPACT_PROOF": {"EVIDENCE_QUALITY_GATE", "CONFIRMED", "INSUFFICIENT", "VALIDATED", "FALSE_POSITIVE"},
        "INSUFFICIENT": {"VALIDATION_PENDING", "CANDIDATE", "VALIDATED", "CLOSED"},
        "EVIDENCE_QUALITY_GATE": {"CONFIRMED", "VALIDATED", "INCONCLUSIVE", "FALSE_POSITIVE"},
        "CONFIRMED": {"REPORTED", "FIXED", "ACCEPTED_RISK", "RETEST", "RETESTING"},
        "REPORTED": {"RETEST", "RETESTING", "FIXED", "CLOSED"},
        "RETEST": {"RETESTING", "FIXED", "NOT_FIXED", "CONFIRMED", "PATCHED"},
        "RETESTING": {"FIXED", "NOT_FIXED", "CLOSED", "REOPENED", "CONFIRMED", "PATCHED"},
        "FIXED": {"RETEST", "RETESTING", "CONFIRMED", "REOPENED", "CLOSED"},
        "NOT_FIXED": {"CONFIRMED", "REOPENED", "RETEST", "FIXED"},
        "REOPENED": {"PRECONDITION_CHECK", "VALIDATION_PENDING", "VALIDATING", "FIXED", "CONFIRMED"},
        "ACCEPTED_RISK": {"REOPENED", "CLOSED", "RETEST"},
        "FALSE_POSITIVE": {"REOPENED", "CLOSED"},
        "CLOSED": {"REOPENED"},
    }

    # Evidence Level Mapping (V8 §26, V9.1 §19)
    EVIDENCE_LEVELS = {
        "E0": "Observation (Port, Banner, Header, HTTP 200)",
        "E1": "Technical Indicator (Reflected input, Error signal, Version candidate)",
        "E2": "Reproducible Vulnerability (Controlled non-destructive verification)",
        "E3": "Demonstrated Security Impact (Conclusive proof of boundary violation)",
        "E4": "Full Impact Evidence (Authorized deep demonstration in lab or explicitly approved)",
    }

    @classmethod
    def can_transition(cls, current_state: str, next_state: str) -> bool:
        curr = current_state.upper()
        nxt = next_state.upper()
        if curr == nxt:
            return True
        allowed = cls.VALID_TRANSITIONS.get(curr, set())
        return nxt in allowed

    @classmethod
    def calculate_evidence_score(
        cls,
        evidence_level: str = "E0",
        *,
        has_corroboration: bool = False,
        has_screenshot: bool = False,
        has_controlled_reproduction: bool = False,
        has_cryptographic_hash: bool = True,
    ) -> int:
        """Calculate evidence score (0-100) per V8 §26 & §27."""
        base_scores = {
            "E0": 10,
            "E1": 30,
            "E2": 55,
            "E3": 75,
            "E4": 85,
        }
        score = base_scores.get(evidence_level.upper(), 10)
        if has_corroboration:
            score += 5
        if has_screenshot:
            score += 5
        if has_controlled_reproduction:
            score += 10
        if has_cryptographic_hash:
            score += 5
        return min(100, max(0, score))
