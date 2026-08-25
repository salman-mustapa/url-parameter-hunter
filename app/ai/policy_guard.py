"""AI Tool-Calling Policy Guard (V8 §11).

Enforces:
AI Action Proposal → Tool Registry Check → Scope/Policy Check → Execution → Structured Result.
AI cannot override policy: ALLOW, DENY, REQUIRES_APPROVAL.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from app.scope.guard import ScopeDecision, ScopeGuard
from app.services.capability_registry import AssessmentProfile, ValidationLevel, capability_registry

logger = logging.getLogger("ai.policy_guard")


class AiToolPolicyGuard:
    """Evaluates AI-generated action proposals against scope and capability policies (V8 §11)."""

    @classmethod
    def evaluate_proposal(
        cls,
        proposal: Dict[str, Any],
        root_domain: str,
        profile: str = "standard",
        validation_level: str = "L2_SAFE_ACTIVE",
        allowed_hosts: Optional[list] = None,
        excluded_hosts: Optional[list] = None,
        is_lab: bool = False,
    ) -> Dict[str, Any]:
        """Evaluates an AI action proposal. Returns verdict: ALLOW, DENY, or REQUIRES_APPROVAL."""
        action = proposal.get("action", "run_check")
        module = proposal.get("module", "")
        target = proposal.get("target", root_domain)
        prop_risk = proposal.get("risk_level", "L2_SAFE_ACTIVE")

        # 1. Capability check if module corresponds to a registered capability
        cap_name = module or action
        cap = capability_registry.get_capability(cap_name)

        if cap:
            cap_eval = capability_registry.is_capability_allowed(
                capability_name=cap_name,
                profile=profile,
                validation_level=validation_level,
                is_lab=is_lab,
            )
            if not cap_eval["allowed"]:
                return {
                    "verdict": cap_eval["verdict"],
                    "reason": f"AI proposal blocked by Capability Policy: {cap_eval['reason']}",
                    "proposal": proposal,
                }

        # 2. ScopeGuard check
        scope_res = ScopeGuard.check(
            target=target,
            root_domain=root_domain,
            action=action,
            capability=cap_name if cap else None,
            profile=profile,
            validation_level=validation_level,
            allowed_hosts=allowed_hosts,
            excluded_hosts=excluded_hosts,
            is_lab=is_lab,
        )

        decision = scope_res.get("decision", ScopeDecision.DENIED.value)
        reason = scope_res.get("reason", "Scope check concluded.")

        logger.info("AI Action proposal [%s on %s] evaluated: %s (%s)", action, target, decision, reason)

        return {
            "verdict": decision,
            "reason": reason,
            "proposal": proposal,
        }
