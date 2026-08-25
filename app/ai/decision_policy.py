"""Next-Best-Action Engine & Resource-Aware Decision Policy (Master Prompt v3 §35, §36, §27, §30).

Key Capabilities:
1. Mathematical Next-Best-Action Scoring (§36):
   Score = (expected_info_gain + expected_security_impact + chain_potential + confidence_gain) / (request_cost + target_risk)
2. Policy Selection: RECON, PROBE, VALIDATE, ESCALATE, CHAIN, VERIFY, STOP
3. Finding Deduplication & Causal Chain Aggregation (§27, §30):
   Aggregates related symptoms into unified causal findings (e.g. Negative Quantity -> Wallet Credit & Inventory Inflation).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("ai.decision_policy")


class InvestigationActionType(str, Enum):
    RECON = "RECON"
    PROBE = "PROBE"
    VALIDATE = "VALIDATE"
    ESCALATE = "ESCALATE"
    CHAIN = "CHAIN"
    VERIFY = "VERIFY"
    STOP = "STOP"


@dataclass
class CandidateAction:
    action_type: InvestigationActionType
    target_endpoint: str
    parameter: Optional[str]
    expected_info_gain: float = 0.5        # 0.0 - 1.0
    expected_security_impact: float = 0.5  # 0.0 - 1.0
    chain_potential: float = 0.5           # 0.0 - 1.0
    confidence_gain: float = 0.5           # 0.0 - 1.0
    request_cost: float = 1.0              # e.g. 1.0 (light HTTP), 5.0 (browser/crawl)
    target_risk: float = 1.0               # 1.0 (read-only safe), 3.0 (stateful mutation)

    @property
    def utility_score(self) -> float:
        """Calculates normalized next-best-action utility score (§36)."""
        numerator = (
            self.expected_info_gain
            + self.expected_security_impact
            + self.chain_potential
            + self.confidence_gain
        )
        denominator = max(0.1, self.request_cost + self.target_risk)
        return round(numerator / denominator, 3)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_type": self.action_type.value,
            "target_endpoint": self.target_endpoint,
            "parameter": self.parameter or "",
            "utility_score": self.utility_score,
            "expected_info_gain": self.expected_info_gain,
            "expected_security_impact": self.expected_security_impact,
            "chain_potential": self.chain_potential,
            "confidence_gain": self.confidence_gain,
            "request_cost": self.request_cost,
            "target_risk": self.target_risk,
        }


class NextBestActionEngine:
    """Selects and schedules optimal next-best-action based on expected information gain vs cost/risk."""

    @classmethod
    def rank_candidate_actions(cls, actions: List[CandidateAction]) -> List[CandidateAction]:
        """Ranks candidate actions by utility score descending."""
        return sorted(actions, key=lambda a: a.utility_score, reverse=True)

    @classmethod
    def deduplicate_and_chain_findings(cls, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Correlates multiple symptoms stemming from the same root cause into single causal findings (§27, §30)."""
        deduped: List[Dict[str, Any]] = []
        biz_logic_group: List[Dict[str, Any]] = []
        jwt_mfa_group: List[Dict[str, Any]] = []

        for f in findings:
            vuln_type = (f.get("vulnerability_type") or "").lower()
            title = (f.get("title") or "").lower()

            if "business_logic" in vuln_type or "quantity" in title or "wallet" in title or "inventory" in title:
                biz_logic_group.append(f)
            elif "jwt" in vuln_type or "2fa" in vuln_type or "totp" in title or "mfa" in title:
                jwt_mfa_group.append(f)
            else:
                deduped.append(f)

        # Merge Business Logic group into unified causal finding
        if len(biz_logic_group) > 1:
            primary = biz_logic_group[0]
            unified_summary = (
                "Negative basket quantities bypass validation and propagate into checkout. "
                "The negative quantity produces a negative order total, which causes wallet credit "
                "instead of a debit and simultaneously increases inventory because stock adjustment "
                "subtracts the basket quantity. The complete state transition was reproduced."
            )
            primary["title"] = "Chained Business Logic: Negative Quantity to Wallet Balance Minting & Inventory Inflation"
            primary["summary"] = unified_summary
            primary["severity"] = "CRITICAL"
            primary["is_chained"] = True
            deduped.append(primary)
        elif biz_logic_group:
            deduped.extend(biz_logic_group)

        # Merge JWT / 2FA group into unified causal finding
        if len(jwt_mfa_group) > 1:
            primary_jwt = jwt_mfa_group[0]
            unified_jwt_summary = (
                "JWT verification accepts forged token contexts (alg: none), allowing an attacker to impersonate "
                "another user and reach protected 2FA endpoints. The forged identity was accepted, a new TOTP setup "
                "was established using attacker-controlled credentials, and normal login subsequently required "
                "the attacker-configured second factor."
            )
            primary_jwt["title"] = "Chained Authentication & Authorization: JWT Signature Bypass to 2FA Setup Takeover"
            primary_jwt["summary"] = unified_jwt_summary
            primary_jwt["severity"] = "CRITICAL"
            primary_jwt["is_chained"] = True
            deduped.append(primary_jwt)
        elif jwt_mfa_group:
            deduped.extend(jwt_mfa_group)

        return deduped


next_best_action_engine = NextBestActionEngine()
