"""NoSQL Injection Validation Specialist (Pentest Spec §5, §6).

Evaluates NoSQL (MongoDB, CouchDB, DynamoDB) injection vectors:
- Operator Injection: {"username": {"$ne": ""}, "password": {"$ne": ""}}
- Boolean Evaluation: {"$gt": ""}
- Regex Probes: {"username": {"$regex": "^admin.*"}}
- JavaScript Evaluation: {"$where": "this.password.match(/^a/)"}
- Query parameter array/object mutations (e.g. user[$ne]=admin)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("validation.nosqli")


@dataclass
class NoSQLiValidationResult:
    is_vulnerable: bool
    technique: str  # operator_ne, operator_gt, regex_leak, where_eval
    parameter: str
    target_url: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0


class NoSQLiValidator:
    """Specialist validator for NoSQL injection vulnerabilities."""

    OPERATOR_PROBES = [
        ({"$ne": "__invalid_random_val__"}, "operator_ne"),
        ({"$gt": ""}, "operator_gt"),
        ({"$regex": ".*"}, "regex_leak"),
    ]

    def evaluate_differential(
        self,
        endpoint_url: str,
        parameter_name: str,
        baseline_response: Dict[str, Any],       # status: 401 or empty list
        mutated_true_response: Dict[str, Any],   # status: 200 or populated data
        mutated_false_response: Dict[str, Any],  # status: 401 or empty list
    ) -> NoSQLiValidationResult:
        """Compares baseline vs true condition ($ne: null) vs false condition ($eq: __impossible__)."""
        base_status = baseline_response.get("status_code", 401)
        true_status = mutated_true_response.get("status_code", 401)
        false_status = mutated_false_response.get("status_code", 401)

        true_has_data = mutated_true_response.get("has_records") or (true_status == 200 and base_status in (401, 403, 404))
        false_denied = false_status in (401, 403, 404) or not mutated_false_response.get("has_records")

        is_vuln = bool(true_has_data and false_denied)
        conf = 0.95 if is_vuln else 0.1

        return NoSQLiValidationResult(
            is_vulnerable=is_vuln,
            technique="operator_ne",
            parameter=parameter_name,
            target_url=endpoint_url,
            evidence={
                "baseline_status": base_status,
                "mutated_true_status": true_status,
                "mutated_false_status": false_status,
                "differential_proven": is_vuln,
            },
            confidence=conf,
        )


nosqli_validator = NoSQLiValidator()
