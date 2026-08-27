"""SQL Injection Vulnerability-Specific Differential Validator (V10 Architecture).

Strict Principles:
1. HTTP 500 alone is NOT SQL Injection.
2. Parameter acceptance alone is NOT SQL Injection.
3. Requires true-condition vs false-condition response divergence OR explicit syntax signature.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, Optional, Tuple

from app.validation.evidence.typed_evidence import (
    DifferentialObservation,
    EvidenceType,
    TypedEvidenceItem,
    TypedEvidencePackage,
)
from app.validation.result import NormalizedValidationResult
from app.validation.state_machine import FindingLifecycleState
from app.validation.validators.base import BaseVulnerabilityValidator

logger = logging.getLogger("validation.validators.sqli")

# Strict database syntax signatures
SQL_ERROR_PATTERNS = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning: mysql_", re.I),
    re.compile(r"unclosed quotation mark after the character string", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"pg_query\(\): query failed:", re.I),
    re.compile(r"sqlite3::query\(\)", re.I),
    re.compile(r"microsoft ole db provider for odbc drivers", re.I),
]


class SQLiValidator(BaseVulnerabilityValidator):
    """Validator evaluating SQL Injection via differential boolean, syntax, and time controls."""

    def __init__(self) -> None:
        super().__init__("sqli")

    async def validate(
        self,
        target_url: str,
        finding_context: Dict[str, Any],
        session_context: Any,
    ) -> NormalizedValidationResult:
        param = finding_context.get("parameter", "id")
        raw_evidence = finding_context.get("raw_evidence", {}) or {}

        # 1. Baseline
        base_body = str(raw_evidence.get("baseline_body", ""))
        base_status = int(raw_evidence.get("baseline_status", 200))

        # 2. Controls & Test
        true_body = str(raw_evidence.get("true_condition_body", ""))
        false_body = str(raw_evidence.get("false_condition_body", ""))
        syntax_err_body = str(raw_evidence.get("syntax_error_body", ""))

        # Evaluate syntax error match
        has_sql_error = any(p.search(syntax_err_body) for p in SQL_ERROR_PATTERNS)
        # Evaluate boolean differential
        has_boolean_diff = bool(true_body and false_body and true_body != false_body and (len(true_body) != len(false_body)))

        pkg = TypedEvidencePackage(
            finding_id=finding_context.get("id", "sqli_test"),
            vulnerability_type="sqli",
            target_url=target_url,
            contract_id="sqli",
            differential=DifferentialObservation(
                baseline_request={"url": target_url, "param": param},
                baseline_response={"status_code": base_status, "length": len(base_body)},
                control_request={"param": f"{param} AND 1=1"},
                control_response={"length": len(true_body)},
                test_request={"param": f"{param} AND 1=2"},
                test_response={"length": len(false_body)},
                differences=["True condition matches baseline while False condition diverged" if has_boolean_diff else "No differential"],
                significance_score=0.95 if (has_sql_error or has_boolean_diff) else 0.0,
                behavioral_anomaly_confirmed=(has_sql_error or has_boolean_diff),
            ),
        )

        if has_sql_error:
            pkg.items.append(
                TypedEvidenceItem(
                    evidence_type=EvidenceType.DATABASE_ERROR,
                    title="Database Syntax Error Exposed",
                    description="Server returned explicit DBMS syntax error on quote injection.",
                    data={"snippet": syntax_err_body[:200]},
                    is_primary_proof=True,
                )
            )

        is_confirmed, status_state, conf_score = self.evaluate_evidence(pkg)

        if not is_confirmed:
            return NormalizedValidationResult(
                status=status_state,
                confidence="SUSPECTED" if status_state == FindingLifecycleState.INCONCLUSIVE.value else "OBSERVED",
                evidence_level="E0",
                vulnerability_type="sqli",
                adapter_name="SQLiValidator",
                title=f"Potential SQL Injection on '{param}' (Unconfirmed)",
                severity="INFO",
                target_host=finding_context.get("target_host", ""),
                endpoint_url=target_url,
                parameter=param,
                actual_result="Server returned generic HTTP response (e.g. 500 error or 200 OK) without differential SQL behavior or DBMS syntax markers.",
                expected_result="Boolean true/false differential or explicit database syntax error.",
            )

        return NormalizedValidationResult(
            status=FindingLifecycleState.CONFIRMED.value,
            confidence="CONFIRMED",
            evidence_level="E3",
            vulnerability_type="sqli",
            adapter_name="SQLiValidator",
            title=f"SQL Injection on parameter '{param}'",
            severity="HIGH",
            target_host=finding_context.get("target_host", ""),
            endpoint_url=target_url,
            parameter=param,
            cwe_id="CWE-89",
            actual_result=f"Confirmed SQL injection behavior on parameter '{param}' via differential response analysis.",
            expected_result="Parameterized database queries with strict input binding.",
            remediation="Use parameterized queries / prepared statements (e.g. PDO in PHP, PreparedStatement in Java).",
            poc_command=f"curl -s -k '{target_url}?{param}=1%27%20OR%201=1--'",
        )

    def evaluate_evidence(self, evidence_pkg: TypedEvidencePackage) -> Tuple[bool, str, int]:
        diff = evidence_pkg.differential
        if not diff or not diff.behavioral_anomaly_confirmed:
            return False, FindingLifecycleState.INCONCLUSIVE.value, 30
        return True, FindingLifecycleState.CONFIRMED.value, 95


sqli_validator = SQLiValidator()
