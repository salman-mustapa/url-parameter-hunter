"""Hypothesis Management, Prioritization & Decision Engine (Master Prompt v2 §3, §22, §23, §38).

Key Features:
- Hypothesis Formulation & Tracking (supporting vs contradicting evidence)
- Prioritization Formula (§22):
  Priority = (exploitability * 0.25) + (impact * 0.30) + (confidence * 0.20) + (chain_potential * 0.15) + (business_criticality * 0.10)
- Exploration Budget Management (§23): request, time, depth, and concurrency budgets
- Decision Policy (§38): EXPLORE, VALIDATE, ESCALATE, CHAIN, VERIFY, STOP
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("ai.hypothesis_engine")


class DecisionAction(str, Enum):
    EXPLORE = "EXPLORE"
    VALIDATE = "VALIDATE"
    ESCALATE = "ESCALATE"
    CHAIN = "CHAIN"
    VERIFY = "VERIFY"
    STOP = "STOP"


@dataclass
class HypothesisRecord:
    hypothesis_id: str
    statement: str
    target_endpoint: str
    parameter: Optional[str] = None
    confidence: float = 0.5  # 0.0 - 1.0
    exploitability: float = 0.5
    impact: float = 0.5
    chain_potential: float = 0.5
    business_criticality: float = 0.5
    supporting_evidence: List[str] = field(default_factory=list)
    contradicting_evidence: List[str] = field(default_factory=list)
    observations: List[str] = field(default_factory=list)
    next_test: str = ""
    expected_result: str = ""
    confidence_after_test: Optional[float] = None
    state: str = "OPEN"  # OPEN, VALIDATING, CONFIRMED, REJECTED
    created_at: float = field(default_factory=time.time)

    @property
    def priority_score(self) -> float:
        """Calculates dynamic priority score (§22)."""
        score = (
            (self.exploitability * 0.25)
            + (self.impact * 0.30)
            + (self.confidence * 0.20)
            + (self.chain_potential * 0.15)
            + (self.business_criticality * 0.10)
        )
        return round(score, 3)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "hypothesis": self.statement,
            "statement": self.statement,
            "target_endpoint": self.target_endpoint,
            "parameter": self.parameter,
            "confidence": self.confidence,
            "priority_score": self.priority_score,
            "supporting_evidence": self.supporting_evidence,
            "contradicting_evidence": self.contradicting_evidence,
            "next_test": self.next_test,
            "expected_result": self.expected_result,
            "confidence_after_test": self.confidence_after_test,
            "state": self.state,
        }


@dataclass
class InvestigationBudget:
    max_requests: int = 150
    used_requests: int = 0
    max_time_seconds: float = 600.0
    elapsed_time_seconds: float = 0.0
    max_depth: int = 5
    current_depth: int = 0
    max_concurrency: int = 4

    def can_request(self) -> bool:
        return self.used_requests < self.max_requests

    def record_request(self, count: int = 1) -> None:
        self.used_requests += count


class HypothesisDecisionEngine:
    """Manages active hypotheses, ranks attack priorities, and selects optimal decision policies."""

    def __init__(self) -> None:
        self.hypotheses: Dict[str, HypothesisRecord] = {}
        self.budget = InvestigationBudget()

    def create_hypothesis(
        self,
        statement: str,
        target_endpoint: str,
        parameter: Optional[str] = None,
        initial_confidence: float = 0.5,
        exploitability: float = 0.6,
        impact: float = 0.6,
        chain_potential: float = 0.5,
        business_criticality: float = 0.5,
        next_test: str = "",
        expected_result: str = "",
    ) -> HypothesisRecord:
        """Formulates and records a new attack hypothesis."""
        hyp_id = f"hyp_{uuid.uuid4().hex[:8]}"
        hyp = HypothesisRecord(
            hypothesis_id=hyp_id,
            statement=statement,
            target_endpoint=target_endpoint,
            parameter=parameter,
            confidence=initial_confidence,
            exploitability=exploitability,
            impact=impact,
            chain_potential=chain_potential,
            business_criticality=business_criticality,
            next_test=next_test,
            expected_result=expected_result,
        )
        self.hypotheses[hyp_id] = hyp
        return hyp

    def rank_hypotheses(self) -> List[HypothesisRecord]:
        """Returns active hypotheses sorted by priority score descending."""
        open_hyps = [h for h in self.hypotheses.values() if h.state in ("OPEN", "VALIDATING")]
        return sorted(open_hyps, key=lambda h: h.priority_score, reverse=True)

    def decide_next_action(self, hypothesis: HypothesisRecord) -> DecisionAction:
        """Evaluates investigation state and chooses the optimal policy action (§38)."""
        if not self.budget.can_request():
            logger.info("Exploration budget exhausted for hypothesis %s -> STOP", hypothesis.hypothesis_id)
            return DecisionAction.STOP

        if hypothesis.confidence >= 0.95 and hypothesis.chain_potential >= 0.7:
            return DecisionAction.CHAIN
        elif hypothesis.confidence >= 0.85:
            return DecisionAction.VERIFY
        elif hypothesis.confidence >= 0.60:
            return DecisionAction.ESCALATE
        elif hypothesis.confidence >= 0.35:
            return DecisionAction.VALIDATE
        elif len(hypothesis.contradicting_evidence) >= 2:
            return DecisionAction.STOP
        else:
            return DecisionAction.EXPLORE

    def update_hypothesis_result(
        self,
        hypothesis_id: str,
        observed_result: Dict[str, Any],
        is_supported: bool,
        evidence_note: str,
    ) -> Optional[HypothesisRecord]:
        """Updates hypothesis confidence based on test results."""
        hyp = self.hypotheses.get(hypothesis_id)
        if not hyp:
            return None

        if is_supported:
            hyp.supporting_evidence.append(evidence_note)
            hyp.confidence_after_test = min(1.0, hyp.confidence + 0.3)
            hyp.confidence = hyp.confidence_after_test
            hyp.state = "CONFIRMED" if hyp.confidence >= 0.9 else "VALIDATING"
        else:
            hyp.contradicting_evidence.append(evidence_note)
            hyp.confidence_after_test = max(0.0, hyp.confidence - 0.35)
            hyp.confidence = hyp.confidence_after_test
            if hyp.confidence <= 0.2:
                hyp.state = "REJECTED"

        return hyp

    def get_hypothesis(self, hypothesis_id: str) -> Optional[HypothesisRecord]:
        return self.hypotheses.get(hypothesis_id)

    def add_supporting_evidence(
        self,
        hypothesis_id: str,
        evidence_id: str,
        confidence_boost: float = 0.3,
    ) -> Optional[HypothesisRecord]:
        """Convenience method to register supporting evidence and boost confidence."""
        hyp = self.hypotheses.get(hypothesis_id)
        if not hyp:
            return None
        hyp.supporting_evidence.append(evidence_id)
        hyp.confidence = min(1.0, hyp.confidence + confidence_boost)
        hyp.confidence_after_test = hyp.confidence
        hyp.state = "CONFIRMED" if hyp.confidence >= 0.85 else "VALIDATING"
        return hyp

    def reset(self) -> None:
        self.hypotheses.clear()
        self.budget = InvestigationBudget()


HypothesisEngine = HypothesisDecisionEngine
hypothesis_engine = HypothesisDecisionEngine()
