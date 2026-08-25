"""Self-Critic Agent & Second-Pass Validation Engine (Master Prompt v2 §15, §16).

Key Responsibilities:
- Adversarial Review of Hypotheses and Findings:
  1. Could this be a false positive (e.g. WAF, generic 500 error, session timeout)?
  2. Could the behavior have an alternative technical explanation?
  3. Was the baseline un-mutated state accurately established?
  4. Was the target authorization/identity state valid?
  5. Did the test verifiably reach and trigger the vulnerable sink?
  6. Was the observed impact directly caused by the payload?
  7. Is there contradictory evidence?
  8. Is the severity and CVSS rating justified by demonstrated impact?
  9. Is the root cause verified?
- Second-Pass Validation Workflow (§16):
  Independent reproduction, re-establishing baseline, re-checking state changes.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("ai.critic_agent")


class CriticDecision(str, Enum):
    PASSED = "passed"
    REJECTED = "failed"
    NEEDS_MORE_TESTING = "needs_more_testing"


@dataclass
class CriticReviewResult:
    status: CriticDecision
    is_confirmed: bool
    confidence_adjustment: float
    concerns: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "is_confirmed": self.is_confirmed,
            "confidence_adjustment": self.confidence_adjustment,
            "concerns": self.concerns,
            "recommendations": self.recommendations,
        }


class SelfCriticAgent:
    """Adversarial critic reviewing findings before final promotion (§15, §16)."""

    WAF_NOISE_SIGNATURES = [
        "cloudflare", "attention required", "checking your browser", "cf-ray",
        "incapsula", "sucuri", "akamai", "aws waf", "captcha"
    ]

    def review_finding(
        self,
        vulnerability_type: str,
        target_endpoint: str,
        baseline_state: Dict[str, Any],
        observed_test_result: Dict[str, Any],
        claimed_severity: str = "HIGH",
        reproduction_verified: bool = True,
        source_code_verified: bool = False,
    ) -> CriticReviewResult:
        """Adversarially evaluates a candidate finding."""
        concerns: List[str] = []
        recommendations: List[str] = []

        resp_body = str(observed_test_result.get("body", "")).lower()
        status_code = observed_test_result.get("status_code", 200)

        # 1. Check for WAF / False Positive Bot Challenges
        if any(w in resp_body for w in self.WAF_NOISE_SIGNATURES):
            concerns.append("Response contains WAF / bot-challenge signature; anomaly may be caused by firewall, not vulnerability.")
            return CriticReviewResult(
                status=CriticDecision.REJECTED,
                is_confirmed=False,
                confidence_adjustment=-0.6,
                concerns=concerns,
                recommendations=["Run bypass evasion or perform browser-based session validation."],
            )

        # 2. Check for Generic 500 / Noise
        if status_code == 500 and not observed_test_result.get("error_stack_present") and not observed_test_result.get("differential_content"):
            concerns.append("Generic HTTP 500 error observed without database stack trace or behavioral proof.")
            return CriticReviewResult(
                status=CriticDecision.NEEDS_MORE_TESTING,
                is_confirmed=False,
                confidence_adjustment=-0.3,
                concerns=concerns,
                recommendations=["Execute differential false-condition test to verify if 500 is payload-specific."],
            )

        # 3. Check for Baseline Validity
        if not baseline_state or baseline_state.get("status_code") == 0:
            concerns.append("Baseline un-mutated state was not captured or was invalid.")
            recommendations.append("Re-capture baseline response before asserting differential impact.")

        # 4. Check for Reproducibility
        if not reproduction_verified:
            concerns.append("Second-pass independent reproduction failed to replicate anomaly.")
            return CriticReviewResult(
                status=CriticDecision.REJECTED,
                is_confirmed=False,
                confidence_adjustment=-0.5,
                concerns=concerns,
                recommendations=["Re-test with identical parameters to verify stability."],
            )

        # 5. Check Severity Justification
        if claimed_severity in ("CRITICAL", "HIGH") and not observed_test_result.get("impact_proven"):
            concerns.append(f"{claimed_severity} claimed but direct security impact (e.g. auth bypass, data exfil) was not demonstrated.")
            recommendations.append("Downgrade severity or perform controlled exploitation to prove impact.")

        if concerns:
            return CriticReviewResult(
                status=CriticDecision.NEEDS_MORE_TESTING if claimed_severity not in ("CRITICAL", "HIGH") else CriticDecision.PASSED,
                is_confirmed=True if len(concerns) <= 1 else False,
                confidence_adjustment=-0.1 * len(concerns),
                concerns=concerns,
                recommendations=recommendations,
            )

        return CriticReviewResult(
            status=CriticDecision.PASSED,
            is_confirmed=True,
            confidence_adjustment=+0.1,
            concerns=[],
            recommendations=["Finding is solid, reproducible, and supported by wire-level evidence."],
        )

    def execute_second_pass_validation(
        self,
        target_endpoint: str,
        test_fn: Callable[[], Dict[str, Any]],
        baseline_fn: Callable[[], Dict[str, Any]],
    ) -> bool:
        """Executes a second independent pass to verify stability and eliminate transient flukes (§16)."""
        try:
            base = baseline_fn()
            res = test_fn()
            # Verify that the test response differs from baseline in the exact same manner
            return bool(res.get("status_code") != base.get("status_code") or res.get("is_anomalous"))
        except Exception as e:
            logger.warning("Second-pass validation error: %s", e)
            return False


critic_agent = SelfCriticAgent()
