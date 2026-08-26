"""Abstract Base Class for Modular Attack Techniques (V15 Architecture).

Defines the unified lifecycle for specialist attack modules:
1. discover(target, context) -> List[AttackOpportunity]
2. plan(opportunity) -> AttackPlan
3. validate(opportunity, session) -> ValidationResult
4. collect_evidence(result) -> EvidencePackage
5. score(evidence) -> RiskScore
"""

from __future__ import annotations

import abc
import hashlib
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.core.session_context import SessionContext, SessionResponse
from app.orchestration.attack_opportunity import AttackOpportunity

logger = logging.getLogger("attacks.base")


@dataclass
class AttackPlan:
    plan_id: str = field(default_factory=lambda: f"plan_{uuid.uuid4().hex[:8]}")
    title: str = ""
    attack_type: str = ""
    target: str = ""
    steps: List[str] = field(default_factory=list)
    payloads: List[str] = field(default_factory=list)
    expected_evidence: str = ""
    timeout_seconds: float = 30.0
    context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "title": self.title,
            "attack_type": self.attack_type,
            "target": self.target,
            "steps": self.steps,
            "payloads": self.payloads,
            "expected_evidence": self.expected_evidence,
            "timeout_seconds": self.timeout_seconds,
            "context": self.context,
        }


@dataclass
class ValidationResult:
    is_vulnerable: bool
    confidence: float  # 0.0 to 1.0
    proof_level: str   # P0 (Unverified), P1 (Reflected), P2 (Behavioral Diff), P3 (Confirmed Exploit), P4 (Full RCE/Admin)
    attack_type: str
    target_url: str
    parameter: Optional[str] = None
    baseline_status: int = 0
    exploit_status: int = 0
    evidence: Dict[str, Any] = field(default_factory=dict)
    poc_curl: str = ""
    message: str = ""
    cwe_id: str = "CWE-200"
    severity: str = "INFO"  # CRITICAL, HIGH, MEDIUM, LOW, INFO

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_vulnerable": self.is_vulnerable,
            "confidence": self.confidence,
            "proof_level": self.proof_level,
            "attack_type": self.attack_type,
            "target_url": self.target_url,
            "parameter": self.parameter,
            "baseline_status": self.baseline_status,
            "exploit_status": self.exploit_status,
            "evidence": self.evidence,
            "poc_curl": self.poc_curl,
            "message": self.message,
            "cwe_id": self.cwe_id,
            "severity": self.severity,
        }


@dataclass
class EvidencePackage:
    evidence_id: str = field(default_factory=lambda: f"ev_{uuid.uuid4().hex[:8]}")
    attack_type: str = ""
    target: str = ""
    url: str = ""
    parameter: Optional[str] = None
    proof_data: Dict[str, Any] = field(default_factory=dict)
    raw_request: str = ""
    raw_response: str = ""
    cryptographic_hash: str = ""
    timestamp: float = field(default_factory=time.time)

    def __post_init__(self):
        if not self.cryptographic_hash:
            raw = f"{self.attack_type}|{self.url}|{self.parameter}|{self.timestamp}|{str(self.proof_data)}"
            self.cryptographic_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "attack_type": self.attack_type,
            "target": self.target,
            "url": self.url,
            "parameter": self.parameter,
            "proof_data": self.proof_data,
            "raw_request": self.raw_request,
            "raw_response": self.raw_response,
            "cryptographic_hash": self.cryptographic_hash,
            "timestamp": self.timestamp,
        }


@dataclass
class RiskScore:
    score_0_100: int
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    cvss_v4: float
    cwe_id: str
    impact: str
    likelihood: str


class BaseAttackModule(abc.ABC):
    """Abstract base class for all specialist attack techniques."""

    def __init__(self, attack_type: str, cwe_id: str = "CWE-200", default_severity: str = "MEDIUM") -> None:
        self.attack_type = attack_type
        self.cwe_id = cwe_id
        self.default_severity = default_severity

    @abc.abstractmethod
    async def discover(self, target: str, context: Dict[str, Any]) -> List[AttackOpportunity]:
        """Discovers potential attack opportunities for this technique."""
        pass

    @abc.abstractmethod
    async def plan(self, opportunity: AttackOpportunity) -> AttackPlan:
        """Formulates an offensive execution plan with tailored mutation steps."""
        pass

    @abc.abstractmethod
    async def validate(self, opportunity: AttackOpportunity, session: SessionContext) -> ValidationResult:
        """Executes active validation to prove or disprove the hypothesis."""
        pass

    async def collect_evidence(self, result: ValidationResult) -> EvidencePackage:
        """Packages raw forensics, proof vectors, and cryptographic signatures."""
        return EvidencePackage(
            attack_type=self.attack_type,
            target=result.target_url,
            url=result.target_url,
            parameter=result.parameter,
            proof_data=result.evidence,
            raw_request=result.poc_curl,
            raw_response=str(result.evidence.get("response_sample", "")),
        )

    async def score(self, evidence: EvidencePackage, result: ValidationResult) -> RiskScore:
        """Calculates risk score based on confirmed impact and confidence."""
        sev = result.severity or self.default_severity
        if sev == "CRITICAL":
            score, cvss = 95, 9.5
        elif sev == "HIGH":
            score, cvss = 80, 8.0
        elif sev == "MEDIUM":
            score, cvss = 55, 5.5
        elif sev == "LOW":
            score, cvss = 30, 3.0
        else:
            score, cvss = 10, 1.0

        return RiskScore(
            score_0_100=score,
            severity=sev,
            cvss_v4=cvss,
            cwe_id=self.cwe_id,
            impact=f"Validated {self.attack_type} vulnerability with proof level {result.proof_level}",
            likelihood="HIGH" if result.confidence > 0.8 else "MEDIUM",
        )
