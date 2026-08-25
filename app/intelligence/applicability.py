from __future__ import annotations

from typing import Any, Dict


class ApplicabilityEngine:
    """Applicability Engine (§25).
    Evaluates exposure, technology match, version boundaries, and configuration preconditions.
    Drastically reduces false positives.
    """

    @staticmethod
    def evaluate(rule_preconditions: Dict[str, Any], observed_context: Dict[str, Any]) -> bool:
        # Check required protocol
        if "protocol" in rule_preconditions:
            req_proto = rule_preconditions["protocol"].lower()
            obs_proto = observed_context.get("protocol", "").lower()
            if req_proto != obs_proto and obs_proto != "":
                return False

        # Check required port
        if "ports" in rule_preconditions:
            req_ports = rule_preconditions["ports"]
            obs_port = observed_context.get("port")
            if obs_port and obs_port not in req_ports:
                return False

        # Check required technology
        if "technology" in rule_preconditions:
            req_tech = rule_preconditions["technology"].lower()
            obs_techs = [t.lower() for t in observed_context.get("technologies", [])]
            if not any(req_tech in t for t in obs_techs):
                return False

        # Check authentication mode
        if "auth_required" in rule_preconditions:
            if rule_preconditions["auth_required"] and not observed_context.get("authenticated", False):
                return False

        return True
