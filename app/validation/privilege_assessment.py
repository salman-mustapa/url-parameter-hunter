"""Privilege Boundary Assessment Subsystem (V8 §17).

Evaluates vertical and horizontal authorization boundaries:
Current Identity → Observed Privileges → Potential Escalation Path → Prerequisites → Controlled Proof.

Evidence collected:
- Before-Identity (low-privilege user context)
- After-State (elevated resource or action outcome)
- Specific boundary breached
- Timestamp & cryptographic hash

Safety Rule:
Do NOT automatically change system privileges or user roles permanently on production targets.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("validation.privilege")


class PrivilegeBoundaryValidator:
    """Validator for structured, harmless privilege boundary testing (V8 §17)."""

    @classmethod
    def analyze_boundary_transition(
        cls,
        *,
        source_identity: str,
        source_role: str,
        target_role: str,
        endpoint_accessed: str,
        status_code: int,
        response_body: str,
        expected_forbidden_code: int = 403,
    ) -> Dict[str, Any]:
        """Evaluates whether an access request crossed an unauthorized privilege boundary."""
        now_utc = datetime.now(timezone.utc).isoformat()

        # If lower role accessed administrative/elevated resource with 200 OK
        is_breach = status_code == 200 and ("admin" in endpoint_accessed.lower() or "manage" in endpoint_accessed.lower())

        result = {
            "source_identity": source_identity,
            "source_role": source_role,
            "target_role_required": target_role,
            "endpoint_accessed": endpoint_accessed,
            "observed_status_code": status_code,
            "expected_rejection_code": expected_forbidden_code,
            "boundary_violation_confirmed": is_breach,
            "timestamp": now_utc,
            "finding_type": "privilege_boundary_violation",
            "evidence": {
                "before_identity": f"{source_identity} ({source_role})",
                "after_authorized_state": f"Access granted (Status {status_code}) to {endpoint_accessed}",
                "timestamp": now_utc,
            },
        }

        if is_breach:
            logger.warning("Privilege boundary breach confirmed: %s -> %s on %s", source_role, target_role, endpoint_accessed)

        return result


privilege_boundary_validator = PrivilegeBoundaryValidator()
