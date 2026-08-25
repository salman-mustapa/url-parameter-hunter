"""LDAP & XPath Injection Specialist (Pentest Spec §5).

Evaluates Directory & XML/XPath Injection Vectors:
- LDAP Filter Injection: *)(uid=*))(|(uid=*, *)(&
- XPath Boolean / Expression Injection: ' or '1'='1, '] | //* | /['
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

logger = logging.getLogger("validation.ldap_xpath")


@dataclass
class InjectionAssessmentResult:
    vulnerability_type: str  # LDAP_INJECTION, XPATH_INJECTION
    is_vulnerable: bool
    parameter: str
    target_url: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0


class LdapXPathValidator:
    """Specialist validator for LDAP and XPath injection flaws."""

    LDAP_PROBES = [
        ("*)(uid=*))(|(uid=*", "ldap_wildcard_bypass"),
        ("*)(&", "ldap_filter_and"),
    ]

    XPATH_PROBES = [
        ("' or '1'='1", "xpath_boolean_true"),
        ("' or '1'='2", "xpath_boolean_false"),
        ("'] | //* | /['", "xpath_union_query"),
    ]

    def evaluate_xpath_differential(
        self,
        endpoint_url: str,
        parameter_name: str,
        true_response: Dict[str, Any],
        false_response: Dict[str, Any],
    ) -> InjectionAssessmentResult:
        """Evaluates XPath differential behavior between true condition and false condition."""
        true_status = true_response.get("status_code", 0)
        false_status = false_response.get("status_code", 0)
        true_records = true_response.get("has_data", False)
        false_records = false_response.get("has_data", False)

        is_vuln = (true_status == 200 and true_records) and (false_status != 200 or not false_records)
        return InjectionAssessmentResult(
            vulnerability_type="XPATH_INJECTION",
            is_vulnerable=is_vuln,
            parameter=parameter_name,
            target_url=endpoint_url,
            evidence={
                "true_condition_status": true_status,
                "false_condition_status": false_status,
                "differential_behavior": is_vuln,
            },
            confidence=0.92 if is_vuln else 0.1,
        )

    def evaluate_ldap_differential(
        self,
        endpoint_url: str,
        parameter_name: str,
        injected_response: Dict[str, Any],
        baseline_response: Dict[str, Any],
    ) -> InjectionAssessmentResult:
        """Evaluates LDAP filter bypass response vs baseline invalid response."""
        inj_status = injected_response.get("status_code", 0)
        base_status = baseline_response.get("status_code", 0)
        inj_success = injected_response.get("auth_success", False) or (inj_status == 200 and base_status in (401, 403))

        return InjectionAssessmentResult(
            vulnerability_type="LDAP_INJECTION",
            is_vulnerable=inj_success,
            parameter=parameter_name,
            target_url=endpoint_url,
            evidence={
                "baseline_status": base_status,
                "injected_status": inj_status,
                "auth_bypass_achieved": inj_success,
            },
            confidence=0.90 if inj_success else 0.1,
        )


ldap_xpath_validator = LdapXPathValidator()
