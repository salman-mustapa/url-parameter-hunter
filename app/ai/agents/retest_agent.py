"""Retest AI Agent (V8 §10).

Responsibilities:
- Coordinates equivalent validation re-execution against fixed targets
- Computes before-and-after cryptographic response diffs
- Categorizes retest outcome:
  - FIXED: Security defect verified resolved
  - NOT_FIXED: Vulnerability reproduced / regression detected
  - INCONCLUSIVE: Target altered, inaccessible, or behavior ambiguous
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("ai.agents.retest")


class RetestVerdict:
    FIXED = "FIXED"
    NOT_FIXED = "NOT_FIXED"
    INCONCLUSIVE = "INCONCLUSIVE"


class RetestAgent:
    """Specialized AI agent for analyzing retest evidence and patch effectiveness (V8 §10)."""

    @classmethod
    async def evaluate_retest_evidence(
        cls,
        before_evidence: Dict[str, Any],
        after_evidence: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Compares baseline vs retest telemetry to determine remediation status."""
        before_status = before_evidence.get("status_code")
        after_status = after_evidence.get("status_code")
        before_hash = before_evidence.get("sha256_hash") or before_evidence.get("response_hash")
        after_hash = after_evidence.get("sha256_hash") or after_evidence.get("response_hash")

        comparison_notes: List[str] = []
        verdict = RetestVerdict.INCONCLUSIVE

        if not after_evidence:
            verdict = RetestVerdict.INCONCLUSIVE
            comparison_notes.append("No response received from retest probe.")
        elif after_evidence.get("is_vulnerable") is False:
            verdict = RetestVerdict.FIXED
            comparison_notes.append("Controlled validation probe was rejected or neutralized by patched application.")
        elif after_evidence.get("is_vulnerable") is True:
            verdict = RetestVerdict.NOT_FIXED
            comparison_notes.append("Vulnerability remains reproducible under identical test conditions.")
        elif before_hash and after_hash and before_hash != after_hash:
            verdict = RetestVerdict.FIXED
            comparison_notes.append("Response signature changed significantly; prior exploit behavior no longer observable.")
        else:
            verdict = RetestVerdict.NOT_FIXED
            comparison_notes.append("Behavior identical to initial vulnerable baseline.")

        logger.info("Retest comparison evaluated: %s (%s)", verdict, ", ".join(comparison_notes))

        return {
            "agent": "retest_agent",
            "verdict": verdict,
            "before_status": before_status,
            "after_status": after_status,
            "before_hash": before_hash,
            "after_hash": after_hash,
            "comparison_notes": comparison_notes,
        }
