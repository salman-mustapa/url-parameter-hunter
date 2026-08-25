"""Standardized Specialist Response & Finding Status Model (Master Prompt v2 §34, §39).

Defines the authoritative 7 finding status levels:
- OBSERVED: An abnormal behavior exists.
- SUSPECTED: A vulnerability hypothesis exists.
- LIKELY: Multiple signals support the hypothesis.
- CONFIRMED: The vulnerability was reproducibly demonstrated.
- EXPLOITED: Controlled exploitation crossed a security boundary.
- CHAINED: The vulnerability produced impact through another application component or weakness.
- REJECTED: Evidence disproved the hypothesis.

Enforces the exact Section 39 structured output schema.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("findings.specialist_response")


class FindingStatus(str, Enum):
    OBSERVED = "observed"
    SUSPECTED = "suspected"
    LIKELY = "likely"
    CONFIRMED = "confirmed"
    EXPLOITED = "exploited"
    CHAINED = "chained"
    REJECTED = "rejected"


@dataclass
class TargetLocation:
    asset: str
    endpoint: str
    method: str = "GET"
    parameter: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset": self.asset,
            "endpoint": self.endpoint,
            "method": self.method,
            "parameter": self.parameter or "",
        }


@dataclass
class IdentityContextSummary:
    requester: str = ""
    role: str = ""
    target_identity: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "requester": self.requester,
            "role": self.role,
            "target_identity": self.target_identity,
        }


@dataclass
class HypothesisSummary:
    statement: str
    supporting_evidence: List[str] = field(default_factory=list)
    contradicting_evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "statement": self.statement,
            "supporting_evidence": self.supporting_evidence,
            "contradicting_evidence": self.contradicting_evidence,
        }


@dataclass
class ImpactAssessment:
    confidentiality: str = ""
    integrity: str = ""
    availability: str = ""
    authentication: str = ""
    authorization: str = ""
    business: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "confidentiality": self.confidentiality,
            "integrity": self.integrity,
            "availability": self.availability,
            "authentication": self.authentication,
            "authorization": self.authorization,
            "business": self.business,
        }


@dataclass
class RootCauseAnalysis:
    source: str = ""
    file: str = ""
    line: Optional[int] = None
    function: str = ""
    sink: str = ""
    data_flow: str = ""
    explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "file": self.file,
            "line": self.line,
            "function": self.function,
            "sink": self.sink,
            "data_flow": self.data_flow,
            "explanation": self.explanation,
        }


@dataclass
class CVSSProfile:
    score: Optional[float] = None
    vector: str = ""
    rationale: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "vector": self.vector,
            "rationale": self.rationale,
        }


@dataclass
class CriticReviewSummary:
    status: str = "passed"  # passed, failed, needs_more_testing
    concerns: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "concerns": self.concerns,
        }


@dataclass
class SpecialistResponseV2:
    status: FindingStatus
    title: str
    vulnerability_type: str
    severity: str
    confidence: float
    target: TargetLocation
    hypothesis: HypothesisSummary
    identity: IdentityContextSummary = field(default_factory=IdentityContextSummary)
    baseline: Dict[str, Any] = field(default_factory=dict)
    tests: List[Dict[str, Any]] = field(default_factory=list)
    observations: List[str] = field(default_factory=list)
    state_changes: List[Dict[str, Any]] = field(default_factory=list)
    exploitability: Dict[str, Any] = field(default_factory=lambda: {"confirmed": False, "evidence": []})
    impact: ImpactAssessment = field(default_factory=ImpactAssessment)
    attack_chain: List[Dict[str, Any]] = field(default_factory=list)
    root_cause: RootCauseAnalysis = field(default_factory=RootCauseAnalysis)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    reproduction_steps: List[str] = field(default_factory=list)
    remediation: List[str] = field(default_factory=list)
    cvss: CVSSProfile = field(default_factory=CVSSProfile)
    critic_review: CriticReviewSummary = field(default_factory=CriticReviewSummary)

    def to_dict(self) -> Dict[str, Any]:
        """Returns the exact §39 / §42 JSON schema representation."""
        return {
            "status": self.status.value,
            "title": self.title,
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "target": self.target.to_dict(),
            "identity": self.identity.to_dict(),
            "hypothesis": self.hypothesis.to_dict(),
            "baseline": self.baseline,
            "tests": self.tests,
            "observations": self.observations,
            "state_changes": self.state_changes,
            "exploitability": self.exploitability,
            "impact": self.impact.to_dict(),
            "attack_chain": self.attack_chain,
            "root_cause": self.root_cause.to_dict(),
            "evidence": self.evidence,
            "reproduction_steps": self.reproduction_steps,
            "remediation": self.remediation,
            "cvss": self.cvss.to_dict(),
            "critic_review": self.critic_review.to_dict(),
        }


# Section 42 Schema alias
SpecialistResponseV3 = SpecialistResponseV2
