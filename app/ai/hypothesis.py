"""Hypothesis Engine & Reasoning Workflow (V8 §35).

Transforms analyst theories or AI hunches into structured, safe test sequences:
States:
- IDEA
- TESTING
- SUPPORTED
- CONFIRMED
- REJECTED
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.ai.gateway import ai_gateway

logger = logging.getLogger("ai.hypothesis")


class HypothesisState:
    IDEA = "IDEA"
    TESTING = "TESTING"
    SUPPORTED = "SUPPORTED"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"


@dataclass
class HypothesisPlan:
    hypothesis_id: str
    title: str
    description: str
    state: str
    relevant_assets: List[str]
    existing_evidence: List[str]
    preconditions: List[str]
    safe_test_sequence: List[Dict[str, Any]]
    expected_outcomes: List[str]
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class HypothesisEngine:
    """Formulates and tracks security hypotheses through safe validation (V8 §35)."""

    @classmethod
    async def create_hypothesis(
        cls,
        title: str,
        description: str,
        context_assets: List[str],
        known_techs: List[str],
    ) -> HypothesisPlan:
        """Formulates an actionable test plan for a given security hypothesis."""
        hyp_id = f"hyp_{uuid.uuid4().hex[:8]}"

        # Prompt AI to decompose hypothesis into safe validation steps
        prompt = f"""Decompose this security hypothesis into a safe, bounded test sequence:
Hypothesis: {title}
Details: {description}
Target Assets: {', '.join(context_assets[:10])}
Technologies: {', '.join(known_techs[:10])}

Return JSON with keys:
- preconditions (list of str)
- safe_test_sequence (list of objects with: step_number, module, target, expected_safe_signal)
- expected_outcomes (list of str)
"""
        res = await ai_gateway.complete(prompt, json_mode=True)
        structured = res.get("structured") or {}

        preconditions = structured.get("preconditions") or [
            "Network connectivity established",
            "Target application endpoints responsive",
        ]
        test_seq = structured.get("safe_test_sequence") or [
            {
                "step_number": 1,
                "module": "web",
                "target": context_assets[0] if context_assets else "target",
                "expected_safe_signal": "Response status code and header inspection",
            }
        ]
        expected_outcomes = structured.get("expected_outcomes") or [
            "Identification of authorization disparity or state deviation"
        ]

        plan = HypothesisPlan(
            hypothesis_id=hyp_id,
            title=title,
            description=description,
            state=HypothesisState.IDEA,
            relevant_assets=context_assets,
            existing_evidence=[],
            preconditions=preconditions,
            safe_test_sequence=test_seq,
            expected_outcomes=expected_outcomes,
        )

        logger.info("Created hypothesis plan %s: '%s' with %d test steps", hyp_id, title, len(test_seq))
        return plan

    @classmethod
    def update_state(cls, plan: HypothesisPlan, new_state: str, reason: Optional[str] = None) -> HypothesisPlan:
        if new_state in (
            HypothesisState.IDEA,
            HypothesisState.TESTING,
            HypothesisState.SUPPORTED,
            HypothesisState.CONFIRMED,
            HypothesisState.REJECTED,
        ):
            plan.state = new_state
            logger.info("Hypothesis %s transitioned to %s (reason: %s)", plan.hypothesis_id, new_state, reason)
        return plan


hypothesis_engine = HypothesisEngine()
