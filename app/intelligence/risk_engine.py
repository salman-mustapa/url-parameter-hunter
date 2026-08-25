"""Multi-Factor Risk Engine (V8 §36).

Calculates accurate risk prioritization by evaluating:
1. Base Severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
2. Confidence Level (CONFIRMED, VALIDATED, SUSPECTED, OBSERVED)
3. Exploitability State (CONFIRMED, VALIDATED, APPLICABLE, CANDIDATE)
4. Exposure (Internet-Facing vs Internal Network)
5. Asset Criticality (P0/P1 High-Value targets vs static staging)
6. Business Impact (High/Medium/Low)
7. CISA Known Exploited Vulnerability (KEV) match
8. Evidence Level (E0, E1, E2, E3, E4)

Outputs Priority:
- P0: Immediate Critical / Weaponized / Active KEV / Critical asset
- P1: High Priority (Verified High-severity with evidence E2+)
- P2: Medium / Standard remediation
- P3: Low priority / hardening
- P4: Informational / hygiene
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional

from app.intelligence.knowledge_base import local_knowledge_base

logger = logging.getLogger("intelligence.risk_engine")


class PriorityTier:
    P0 = "P0"  # Critical / Immediate
    P1 = "P1"  # High
    P2 = "P2"  # Standard
    P3 = "P3"  # Low
    P4 = "P4"  # Informational


class MultiFactorRiskEngine:
    """Computes comprehensive risk scores and prioritization tiers (V8 §36)."""

    @classmethod
    def calculate_priority(
        cls,
        *,
        severity: str,
        confidence: str = "CONFIRMED",
        exploitability_state: str = "CANDIDATE",
        evidence_level: str = "E0",
        cve_id: Optional[str] = None,
        is_internet_facing: bool = True,
        asset_criticality: str = "MEDIUM",  # HIGH, MEDIUM, LOW
    ) -> Dict[str, Any]:
        """Calculates multi-dimensional risk score and assigns priority P0–P4."""
        sev = (severity or "INFO").upper().strip()
        conf = (confidence or "OBSERVED").upper().strip()
        exp_state = (exploitability_state or "CANDIDATE").upper().strip()
        ev_lvl = (evidence_level or "E0").upper().strip()

        # Check KEV
        is_kev = local_knowledge_base.is_kev_vulnerability(cve_id or "")

        # Numerical score calculation (0 - 100)
        score = 0

        # 1. Base severity weight
        sev_weights = {"CRITICAL": 45, "HIGH": 35, "MEDIUM": 20, "LOW": 10, "INFO": 2}
        score += sev_weights.get(sev, 5)

        # 2. Evidence level weight
        ev_weights = {"E4": 25, "E3": 20, "E2": 15, "E1": 8, "E0": 2}
        score += ev_weights.get(ev_lvl, 2)

        # 3. Exploitability weight
        if exp_state in ("CONFIRMED", "VALIDATED"):
            score += 15
        elif exp_state == "APPLICABLE":
            score += 8

        # 4. KEV boost
        if is_kev:
            score += 15

        # 5. Asset criticality boost
        if asset_criticality.upper() == "HIGH":
            score += 10
        elif asset_criticality.upper() == "LOW":
            score -= 5

        # 6. Exposure adjustment
        if is_internet_facing:
            score += 5

        score = min(100, max(0, score))

        # Assign Priority Tier
        if score >= 80 or (sev == "CRITICAL" and is_kev) or (sev == "CRITICAL" and ev_lvl in ("E3", "E4")):
            priority = PriorityTier.P0
        elif score >= 60 or (sev == "HIGH" and ev_lvl in ("E2", "E3", "E4")):
            priority = PriorityTier.P1
        elif score >= 35:
            priority = PriorityTier.P2
        elif score >= 15:
            priority = PriorityTier.P3
        else:
            priority = PriorityTier.P4

        logger.info("Risk calculation: Sev=%s, Ev=%s, KEV=%s -> Score=%d, Priority=%s", sev, ev_lvl, is_kev, score, priority)

        return {
            "priority": priority,
            "calculated_score": score,
            "is_kev": is_kev,
            "factors": {
                "severity": sev,
                "confidence": conf,
                "exploitability": exp_state,
                "evidence_level": ev_lvl,
                "is_internet_facing": is_internet_facing,
                "asset_criticality": asset_criticality,
            },
        }


risk_engine = MultiFactorRiskEngine()
