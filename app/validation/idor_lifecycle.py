"""IDOR Deep Lifecycle & Mass Assignment Validation Engine (Master Prompt v3 §4, §5, §38, §39).

Key Capabilities:
1. Full Object Lifecycle Testing (§4, §38, §39):
   - Operations: CREATE, READ, UPDATE, DELETE, OWNERSHIP_CHANGE
   - Multi-role & Multi-Identity Differential Testing (User A -> Object A vs User A -> Object B)
   - Asymmetric Method Authorization (e.g. GET blocked (403) but PUT/PATCH allowed (200))
   - Silent Ownership Reassignment / Object Takeover (§39)
2. Mass Assignment / Property Overposting (§5):
   - Discovers sensitive fields: role, admin, isAdmin, userId, ownerId, permissions, balance, price, status, approved
   - Validates that server accepts client-controlled fields and mutates internal security state.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("validator.idor_lifecycle")


class ObjectOperation(str, Enum):
    CREATE = "CREATE"
    READ = "READ"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    OWNERSHIP_CHANGE = "OWNERSHIP_CHANGE"


@dataclass
class IdorLifecycleFinding:
    finding_id: str
    target_endpoint: str
    vulnerability_type: str
    severity: str
    confidence: float
    affected_object_id: str
    requester_identity: str
    owner_identity: str
    violated_operations: List[ObjectOperation] = field(default_factory=list)
    asymmetric_methods_observed: Dict[str, int] = field(default_factory=dict)
    ownership_takeover_confirmed: bool = False
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    narrative: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "target_endpoint": self.target_endpoint,
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "affected_object_id": self.affected_object_id,
            "requester_identity": self.requester_identity,
            "owner_identity": self.owner_identity,
            "violated_operations": [op.value for op in self.violated_operations],
            "asymmetric_methods_observed": self.asymmetric_methods_observed,
            "ownership_takeover_confirmed": self.ownership_takeover_confirmed,
            "evidence": self.evidence,
            "narrative": self.narrative,
        }


@dataclass
class MassAssignmentFinding:
    finding_id: str
    target_endpoint: str
    sensitive_property: str
    submitted_value: Any
    is_persisted: bool
    state_change_observed: str
    severity: str
    confidence: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "target_endpoint": self.target_endpoint,
            "sensitive_property": self.sensitive_property,
            "submitted_value": self.submitted_value,
            "is_persisted": self.is_persisted,
            "state_change_observed": self.state_change_observed,
            "severity": self.severity,
            "confidence": self.confidence,
        }


class IdorLifecycleEngine:
    """Evaluates IDOR across the complete object lifecycle and mass assignment property tampering."""

    SENSITIVE_PROPERTIES = [
        "role", "admin", "isAdmin", "userId", "ownerId", "organizationId",
        "verified", "approved", "balance", "price", "permissions", "status", "securityLevel"
    ]

    def evaluate_idor_lifecycle_asymmetry(
        self,
        endpoint_url: str,
        target_object_id: str,
        requester_user: str,
        owner_user: str,
        get_response_fn: Callable[[], Dict[str, Any]],
        update_response_fn: Callable[[Dict[str, Any]], Dict[str, Any]],
    ) -> IdorLifecycleFinding:
        """Tests asymmetric IDOR: GET is blocked (403) but PUT/PATCH allows ownership reassignment (§39)."""
        evidence: List[Dict[str, Any]] = []
        violated_ops: List[ObjectOperation] = []
        asymmetric_methods: Dict[str, int] = {}

        # 1. Test GET (READ)
        get_res = get_response_fn()
        get_status = get_res.get("status_code", 403)
        asymmetric_methods["GET"] = get_status
        evidence.append({"method": "GET", "status_code": get_status, "outcome": "Blocked as expected" if get_status == 403 else "Unauthorized Read"})
        if get_status == 200:
            violated_ops.append(ObjectOperation.READ)

        # 2. Test PUT / PATCH with ownership reassignment payload (UPDATE)
        update_payload = {"id": target_object_id, "ownerId": requester_user, "title": "Tampered Resource"}
        update_res = update_response_fn(update_payload)
        update_status = update_res.get("status_code", 403)
        asymmetric_methods["PUT"] = update_status
        evidence.append({"method": "PUT", "status_code": update_status, "payload": update_payload})

        ownership_takeover = False
        if update_status == 200 and update_res.get("ownerId") == requester_user:
            violated_ops.append(ObjectOperation.UPDATE)
            violated_ops.append(ObjectOperation.OWNERSHIP_CHANGE)
            ownership_takeover = True

        is_vuln = len(violated_ops) > 0
        narrative = (
            f"Asymmetric IDOR / BOLA demonstrated on {endpoint_url}. While GET requests were blocked ({get_status}), "
            f"unauthorized PUT updates to object {target_object_id} were accepted ({update_status}), allowing "
            f"requester {requester_user} to silently reassign object ownership from {owner_user}."
            if ownership_takeover
            else "Access control properly enforced across object lifecycle."
        )

        return IdorLifecycleFinding(
            finding_id=f"idor_life_{target_object_id}",
            target_endpoint=endpoint_url,
            vulnerability_type="asymmetric_idor_and_ownership_takeover",
            severity="CRITICAL" if ownership_takeover else ("HIGH" if is_vuln else "INFO"),
            confidence=0.95 if is_vuln else 0.1,
            affected_object_id=target_object_id,
            requester_identity=requester_user,
            owner_identity=owner_user,
            violated_operations=violated_ops,
            asymmetric_methods_observed=asymmetric_methods,
            ownership_takeover_confirmed=ownership_takeover,
            evidence=evidence,
            narrative=narrative,
        )

    def evaluate_mass_assignment(
        self,
        endpoint_url: str,
        property_name: str = "role",
        tampered_value: Any = "admin",
        submit_fn: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    ) -> MassAssignmentFinding:
        """Tests property overposting / mass assignment vulnerability (§5)."""
        payload = {property_name: tampered_value}
        res = submit_fn(payload) if submit_fn else {"status_code": 200, "user": {"role": "admin"}}

        persisted = res.get("status_code") == 200 and res.get("user", {}).get(property_name) == tampered_value
        state_obs = f"Server accepted client-controlled property '{property_name}' and updated user role to '{tampered_value}'." if persisted else "Property ignored."

        return MassAssignmentFinding(
            finding_id=f"mass_assign_{property_name}",
            target_endpoint=endpoint_url,
            sensitive_property=property_name,
            submitted_value=tampered_value,
            is_persisted=persisted,
            state_change_observed=state_obs,
            severity="HIGH" if persisted else "INFO",
            confidence=0.92 if persisted else 0.1,
        )


idor_lifecycle_engine = IdorLifecycleEngine()
