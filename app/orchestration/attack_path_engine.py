"""Attack Path Engine & Precondition Graph Reasoner (Specialist Agent V2 §7, §19, §37).

Responsibilities:
- Graph traversal and precondition analysis.
- Chains discovered observations into structured, ranked AttackPathCandidates:
  Example: Exposed API -> JWT Token -> Object ID -> User Context -> Authorization Weakness -> Privilege Escalation.
- Ranks attack path feasibility and suggests required specialist agents and skills.
- Does NOT execute the chain directly (leaves execution to authorized specialist validators).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("orchestration.attack_path_engine")


class AttackPathStage(str, Enum):
    INITIAL_EXPOSURE = "Initial Exposure"
    CREDENTIAL_OR_TOKEN_ACQUIRED = "Credential / Token Acquired"
    AUTHENTICATION_BYPASS = "Authentication Bypass"
    AUTHORIZATION_WEAKNESS = "Authorization Weakness"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DATA_EXFILTRATION = "Data Exfiltration"
    REMOTE_CODE_EXECUTION = "Remote Code Execution"


@dataclass
class AttackPathStep:
    step_number: int
    stage: AttackPathStage
    source_observation: str
    target_node: str
    precondition_met: bool
    recommended_agent: str
    recommended_skill: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackPathCandidate:
    path_id: str
    title: str
    target_root: str
    feasibility_score: float  # 0.0 - 1.0
    impact_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    steps: List[AttackPathStep] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_id": self.path_id,
            "title": self.title,
            "target_root": self.target_root,
            "feasibility_score": self.feasibility_score,
            "impact_level": self.impact_level,
            "total_steps": len(self.steps),
            "steps": [
                {
                    "step_number": s.step_number,
                    "stage": s.stage.value,
                    "source_observation": s.source_observation,
                    "target_node": s.target_node,
                    "precondition_met": s.precondition_met,
                    "recommended_agent": s.recommended_agent,
                    "recommended_skill": s.recommended_skill,
                    "details": s.details,
                }
                for s in self.steps
            ],
            "created_at": self.created_at,
        }


class AttackPathEngine:
    """Graph traversal and precondition reasoning engine for multi-step attack paths."""

    def __init__(self) -> None:
        self._active_candidates: Dict[str, AttackPathCandidate] = {}

    def analyze_attack_paths(
        self,
        target: str,
        observations: List[Dict[str, Any]],
    ) -> List[AttackPathCandidate]:
        """Analyzes observations on a target and constructs ranked attack paths."""
        candidates: List[AttackPathCandidate] = []

        has_api = any("api" in str(o.get("endpoint", "")).lower() or o.get("type") == "api_endpoint" for o in observations)
        has_jwt = any("jwt" in str(o.get("type", "")).lower() or "token" in str(o.get("data", "")).lower() for o in observations)
        has_idor_param = any(p in ["id", "user_id", "account_id", "uuid", "doc_id"] for o in observations for p in o.get("params", []))
        has_admin_portal = any("admin" in str(o.get("endpoint", "")).lower() or o.get("type") == "admin_portal" for o in observations)
        has_sqli_indicator = any(o.get("type") == "sqli_reflection" or "sql" in str(o.get("type", "")).lower() for o in observations)

        # Path 1: API -> JWT Token -> IDOR -> Data Exfiltration
        if has_api and has_jwt and has_idor_param:
            path_id = f"path_api_idor_{int(time.time()*1000)}"
            steps = [
                AttackPathStep(
                    step_number=1,
                    stage=AttackPathStage.INITIAL_EXPOSURE,
                    source_observation="Public REST/GraphQL API Discovered",
                    target_node=target,
                    precondition_met=True,
                    recommended_agent="APIDiscoveryAgent",
                    recommended_skill="api-discovery",
                ),
                AttackPathStep(
                    step_number=2,
                    stage=AttackPathStage.CREDENTIAL_OR_TOKEN_ACQUIRED,
                    source_observation="JWT Bearer Token / Session Header in API Response",
                    target_node=f"{target}/api/auth",
                    precondition_met=True,
                    recommended_agent="JWTAgent",
                    recommended_skill="jwt-security",
                ),
                AttackPathStep(
                    step_number=3,
                    stage=AttackPathStage.AUTHORIZATION_WEAKNESS,
                    source_observation="Object ID Parameter Exposed in Authenticated Route",
                    target_node=f"{target}/api/users/{{id}}",
                    precondition_met=True,
                    recommended_agent="IDORAgent",
                    recommended_skill="idor-validation",
                ),
                AttackPathStep(
                    step_number=4,
                    stage=AttackPathStage.DATA_EXFILTRATION,
                    source_observation="Unauthorized Object Access Differential",
                    target_node=f"{target}/api/data",
                    precondition_met=False,  # Needs validation
                    recommended_agent="IdentityContextAgent",
                    recommended_skill="authorization-testing",
                ),
            ]
            cand = AttackPathCandidate(
                path_id=path_id,
                title="API Authentication to Broken Object Level Authorization (IDOR) Exfiltration",
                target_root=target,
                feasibility_score=0.88,
                impact_level="HIGH",
                steps=steps,
            )
            candidates.append(cand)
            self._active_candidates[path_id] = cand

        # Path 2: Admin Portal Exposure -> SQL Injection -> Privilege Escalation
        if has_admin_portal and has_sqli_indicator:
            path_id = f"path_admin_sqli_{int(time.time()*1000)}"
            steps = [
                AttackPathStep(
                    step_number=1,
                    stage=AttackPathStage.INITIAL_EXPOSURE,
                    source_observation="Admin Portal / Login Form Exposed",
                    target_node=f"{target}/admin/login",
                    precondition_met=True,
                    recommended_agent="ArtifactExposureAgent",
                    recommended_skill="content-discovery",
                ),
                AttackPathStep(
                    step_number=2,
                    stage=AttackPathStage.AUTHENTICATION_BYPASS,
                    source_observation="SQL Injection reflection observed on login parameter",
                    target_node=f"{target}/admin/login",
                    precondition_met=True,
                    recommended_agent="SQLiAgent",
                    recommended_skill="sqli-validation",
                ),
                AttackPathStep(
                    step_number=3,
                    stage=AttackPathStage.PRIVILEGE_ESCALATION,
                    source_observation="Administrative Dashboard Session Established",
                    target_node=f"{target}/admin/dashboard",
                    precondition_met=False,  # Needs validation
                    recommended_agent="PrivilegeEscalationAgent",
                    recommended_skill="privilege-escalation",
                ),
            ]
            cand = AttackPathCandidate(
                path_id=path_id,
                title="Admin Portal SQL Injection to Full Administrative Dashboard Takeover",
                target_root=target,
                feasibility_score=0.92,
                impact_level="CRITICAL",
                steps=steps,
            )
            candidates.append(cand)
            self._active_candidates[path_id] = cand

        # Sort candidates by feasibility descending
        candidates.sort(key=lambda c: c.feasibility_score, reverse=True)
        return candidates

    def get_candidate(self, path_id: str) -> Optional[AttackPathCandidate]:
        return self._active_candidates.get(path_id)

    def reset(self) -> None:
        self._active_candidates.clear()


attack_path_engine = AttackPathEngine()
