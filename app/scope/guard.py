"""Scope Engine & Authorization Guard (V8 §3, §4, §5, §102).

Enforces: REQUEST → SCOPE & CAPABILITY CHECK → ALLOW / DENY / REQUIRES_APPROVAL.
Levels:
  L0 OBSERVE
  L1 PASSIVE
  L2 SAFE_ACTIVE
  L3 CONTROLLED
  L4 HIGH_RISK

No scanner, worker, or AI tool adapter may bypass this gate.
"""

from __future__ import annotations

import enum
import ipaddress
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from app.services.capability_registry import AssessmentProfile, ValidationLevel, capability_registry

logger = logging.getLogger("scope.guard")


class ScopeDecision(str, enum.Enum):
    ALLOWED = "ALLOWED"
    DENIED = "DENIED"
    REQUIRES_APPROVAL = "REQUIRES_APPROVAL"


class ScopeGuard:
    """Central Scope & Authorization Gatekeeper (V8 §3, §5)."""

    L4_HIGH_RISK_MODULES = {
        "mass_data_extraction",
        "credential_brute_force_unbounded",
        "dos_testing",
        "persistence-simulation",
        "persistence_check",
        "arbitrary_rce_payload",
        "lateral-movement-simulation",
        "unauthorized_privilege_escalation",
    }

    L3_CONTROLLED_MODULES = {
        "sqli_validation",
        "xss_validation",
        "ssrf_callback",
        "path_traversal",
        "open_redirect",
        "auth_bypass",
        "idor_validation",
        "credential-assessment",
        "payload-validation",
        "privilege-validation",
        "authentication",
        "authorization",
    }

    @classmethod
    def check(
        cls,
        *,
        target: str,
        root_domain: str,
        action: str = "read_only",
        capability: Optional[str] = None,
        profile: str = "standard",
        validation_level: str = "L2_SAFE_ACTIVE",
        allowed_hosts: Optional[List[str]] = None,
        excluded_hosts: Optional[List[str]] = None,
        allowed_cidrs: Optional[List[str]] = None,
        allowed_ports: Optional[List[int]] = None,
        port: Optional[int] = None,
        is_recursive: bool = True,
        is_lab: bool = False,
    ) -> Dict[str, Any]:
        """Evaluate if an action/capability against a target is within authorized scope."""
        # 1. Capability & Profile check (V8 §4, §5)
        if capability:
            cap_eval = capability_registry.is_capability_allowed(
                capability_name=capability,
                profile=profile,
                validation_level=validation_level,
                is_lab=is_lab,
            )
            if not cap_eval["allowed"]:
                return {
                    "decision": ScopeDecision[cap_eval["verdict"]].value,
                    "reason": cap_eval["reason"],
                    "target": target,
                    "action": action,
                    "capability": capability,
                }

        # 2. High-risk L4 safety check (V8 §3)
        if action in cls.L4_HIGH_RISK_MODULES or validation_level == ValidationLevel.L4_HIGH_RISK:
            if profile.lower() != AssessmentProfile.ADVERSARY_SIMULATION:
                return {
                    "decision": ScopeDecision.DENIED.value,
                    "reason": "L4 High-Risk execution is strictly prohibited outside Adversary Simulation profile.",
                    "target": target,
                    "action": action,
                }
            if not is_lab:
                return {
                    "decision": ScopeDecision.REQUIRES_APPROVAL.value,
                    "reason": "Action classified as L4 High-Risk on production target. Requires explicit operator approval gate and rollback plan.",
                    "target": target,
                    "action": action,
                }

        # Normalize target to hostname/ip
        parsed_host = target
        if "://" in target:
            try:
                parsed_host = urlparse(target).hostname or target
            except Exception:
                parsed_host = target

        parsed_host = (parsed_host or "").lower().strip()
        root_domain = (root_domain or "").lower().strip()

        # 3. Check Excluded Hosts
        if excluded_hosts:
            for exc in excluded_hosts:
                exc = exc.lower().strip()
                if parsed_host == exc or parsed_host.endswith(f".{exc}"):
                    return {
                        "decision": ScopeDecision.DENIED.value,
                        "reason": f"Target '{parsed_host}' is explicitly excluded in scope boundary.",
                        "target": target,
                        "action": action,
                    }

        # 4. Host / Domain Scope Check
        is_in_scope = False

        if parsed_host == root_domain:
            is_in_scope = True
        elif is_recursive and parsed_host.endswith(f".{root_domain}"):
            is_in_scope = True
        elif allowed_hosts and parsed_host in [h.lower() for h in allowed_hosts]:
            is_in_scope = True

        # 5. CIDR Scope Check for IP targets
        if not is_in_scope and allowed_cidrs:
            try:
                ip_obj = ipaddress.ip_address(parsed_host)
                for cidr in allowed_cidrs:
                    net = ipaddress.ip_network(cidr, strict=False)
                    if ip_obj in net:
                        is_in_scope = True
                        break
            except ValueError:
                pass

        if not is_in_scope:
            return {
                "decision": ScopeDecision.DENIED.value,
                "reason": f"Target '{parsed_host}' is outside the authorized root domain boundary '{root_domain}'.",
                "target": target,
                "action": action,
            }

        # 6. Port restriction check
        if port and allowed_ports:
            if port not in allowed_ports:
                return {
                    "decision": ScopeDecision.DENIED.value,
                    "reason": f"Port {port} is not in the allowed port scope.",
                    "target": target,
                    "action": action,
                }

        # 7. Controlled Validation check (L3)
        if validation_level == ValidationLevel.L3_CONTROLLED or action in cls.L3_CONTROLLED_MODULES:
            return {
                "decision": ScopeDecision.ALLOWED.value,
                "reason": "Scope verified. L3 Controlled validation active with safety constraints.",
                "target": target,
                "action": action,
            }

        return {
            "decision": ScopeDecision.ALLOWED.value,
            "reason": "Target verified within authorized scope boundary.",
            "target": target,
            "action": action,
        }
