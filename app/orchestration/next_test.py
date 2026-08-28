"""Choose an applicable, evidence-supported test under scope and risk budgets."""

import math
from dataclasses import dataclass

from app.ai.decision_policy import CandidateAction, InvestigationActionType


@dataclass(frozen=True)
class TestCandidate:
    __test__ = False
    test: str
    endpoint: str
    evidence_ids: tuple[str, ...]
    required_evidence: tuple[str, ...]
    relevance: float = 0.5
    impact: float = 0.5
    cost: float = 1
    risk: float = 1

    def __post_init__(self):
        if not all(math.isfinite(v) for v in (self.relevance, self.impact, self.cost, self.risk)):
            raise ValueError("Scores must be finite")
        if (
            not 0 <= self.relevance <= 1
            or not 0 <= self.impact <= 1
            or self.cost <= 0
            or self.risk < 0
        ):
            raise ValueError("Invalid candidate scores")


class NextBestTestEngine:
    def select(self, candidates, evidence, previous_tests, scope, registry, max_risk=2):
        known = {e["id"]: e for e in evidence}
        ranked = []
        for candidate in candidates:
            if not scope.allows(candidate.endpoint) or not registry.get(candidate.test):
                continue
            if candidate.risk > max_risk or candidate.relevance <= 0 or not candidate.evidence_ids:
                continue
            if not set(candidate.evidence_ids) <= known.keys():
                continue
            if any(
                p.get("test") == candidate.test
                and p.get("endpoint") == candidate.endpoint
                and set(p.get("input_evidence_ids", [])) == set(candidate.evidence_ids)
                for p in previous_tests
            ):
                continue
            strength = sum(
                float(known[i].get("confidence", 0)) * float(known[i].get("relevance", 0))
                for i in candidate.evidence_ids
            ) / len(candidate.evidence_ids)
            if not math.isfinite(strength) or not 0 < strength <= 1:
                continue
            action = CandidateAction(
                InvestigationActionType.VALIDATE,
                candidate.endpoint,
                None,
                expected_info_gain=candidate.relevance,
                expected_security_impact=candidate.impact,
                chain_potential=0,
                confidence_gain=strength,
                request_cost=candidate.cost,
                target_risk=candidate.risk,
            )
            ranked.append((action.utility_score, candidate))
        if not ranked:
            return None
        score, best = sorted(ranked, key=lambda item: (-item[0], item[1].test, item[1].endpoint))[0]
        return {
            "test": best.test,
            "endpoint": best.endpoint,
            "reason": "Known evidence is relevant; target is authorized; risk/cost and prior results permit this test",
            "required_evidence": list(best.required_evidence),
            "priority": round(score * 100, 2),
            "evidence_ids": list(best.evidence_ids),
        }
