"""False-Positive Firewall & Deterministic Verification Gate (§47).

Strictly prevents common false positive classifications:
1. HTTP 403/401 is NOT an authentication bypass.
2. HTTP 301/302/307 redirect alone is NOT proof of successful authentication.
3. SQL database syntax error alone is NOT confirmed SQL Injection (requires mathematical canary or differential proof).
4. Plain parameter reflection is NOT confirmed XSS (requires unescaped execution context / browser sink proof).
5. HTTP 200 OK is NOT confirmed IDOR (requires verified multi-identity object ownership boundary crossing).
6. Version banner string match is NOT a confirmed CVE (requires deterministic affected version check & exploitability evidence).
7. Nuclei template match is a CANDIDATE, not automatically a CONFIRMED finding without independent validation.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("validation.false_positive_firewall")


class GateDecision(str, Enum):
    PASS = "PASS"
    REJECTED = "REJECTED"
    NEEDS_REVIEW = "NEEDS_REVIEW"


@dataclass
class FirewallVerdict:
    decision: GateDecision
    rule_id: str
    reason: str
    confidence_penalty: float = 0.0
    recommended_state: str = "CONFIRMED"  # CONFIRMED, CANDIDATE, REJECTED, NEEDS_REVIEW


class FalsePositiveFirewall:
    """Deterministic security gatekeeper that validates candidate findings before confirmation."""

    def __init__(self) -> None:
        self.rules = [
            self._gate_auth_bypass_status_code,
            self._gate_sqli_syntax_error_only,
            self._gate_xss_reflection_only,
            self._gate_idor_status_code_only,
            self._gate_cve_banner_match_only,
            self._gate_nuclei_unverified_candidate,
            self._gate_open_port_not_vulnerability,
            self._gate_empty_or_missing_evidence,
        ]

    def evaluate_finding(self, finding_data: Dict[str, Any], evidence_data: Optional[Dict[str, Any]] = None) -> FirewallVerdict:
        """Run all firewall gates against candidate finding and evidence."""
        evidence = evidence_data or finding_data.get("evidence") or {}
        
        for rule in self.rules:
            verdict = rule(finding_data, evidence)
            if verdict.decision != GateDecision.PASS:
                logger.warning(
                    "FalsePositiveFirewall [%s] triggered for finding '%s': %s",
                    verdict.rule_id,
                    finding_data.get("title") or finding_data.get("type"),
                    verdict.reason
                )
                return verdict

        return FirewallVerdict(
            decision=GateDecision.PASS,
            rule_id="FP-GATE-ALL-PASS",
            reason="All deterministic quality and false-positive gates passed.",
            confidence_penalty=0.0,
            recommended_state="CONFIRMED"
        )

    # -------------------------------------------------------------------------
    # Gate Rules
    # -------------------------------------------------------------------------

    def _gate_auth_bypass_status_code(self, finding: Dict[str, Any], evidence: Dict[str, Any]) -> FirewallVerdict:
        """Rule 1: 403/401/302 is NOT auth bypass."""
        vuln_type = (finding.get("type") or finding.get("title") or "").upper()
        if "AUTH" in vuln_type and ("BYPASS" in vuln_type or "BROKEN" in vuln_type):
            status_code = evidence.get("status_code") or evidence.get("response_status")
            if status_code in (401, 403):
                return FirewallVerdict(
                    decision=GateDecision.REJECTED,
                    rule_id="FP-AUTH-001",
                    reason=f"HTTP {status_code} indicates active access restriction, NOT authentication bypass.",
                    confidence_penalty=1.0,
                    recommended_state="REJECTED"
                )
            if status_code in (301, 302, 303, 307, 308) and not evidence.get("authenticated_session_verified"):
                return FirewallVerdict(
                    decision=GateDecision.NEEDS_REVIEW,
                    rule_id="FP-AUTH-002",
                    reason="Redirect status code without confirmed session state or authenticated body access is insufficient for auth bypass.",
                    confidence_penalty=0.5,
                    recommended_state="CANDIDATE"
                )
            # Require proof of protected resource access
            if not evidence.get("protected_resource_accessed") and not evidence.get("body_differential_confirmed"):
                return FirewallVerdict(
                    decision=GateDecision.NEEDS_REVIEW,
                    rule_id="FP-AUTH-003",
                    reason="Auth bypass candidate lacks proof of protected resource access across anonymous baseline.",
                    confidence_penalty=0.4,
                    recommended_state="CANDIDATE"
                )
        return FirewallVerdict(GateDecision.PASS, "FP-AUTH-PASS", "Auth gate passed.")

    def _gate_sqli_syntax_error_only(self, finding: Dict[str, Any], evidence: Dict[str, Any]) -> FirewallVerdict:
        """Rule 2: Database error message alone is NOT confirmed SQLi."""
        vuln_type = (finding.get("type") or finding.get("title") or "").upper()
        if "SQL" in vuln_type:
            has_canary_calc = evidence.get("canary_calculation_verified", False)
            has_time_delay = evidence.get("time_differential_verified", False)
            has_union_extract = evidence.get("union_extraction_verified", False)
            has_boolean_diff = evidence.get("boolean_differential_verified", False)

            if not any([has_canary_calc, has_time_delay, has_union_extract, has_boolean_diff]):
                if evidence.get("db_error_detected"):
                    return FirewallVerdict(
                        decision=GateDecision.NEEDS_REVIEW,
                        rule_id="FP-SQLI-001",
                        reason="Database syntax error reflection detected without controlled mathematical canary or differential proof. Demoted to candidate.",
                        confidence_penalty=0.35,
                        recommended_state="CANDIDATE"
                    )
        return FirewallVerdict(GateDecision.PASS, "FP-SQLI-PASS", "SQLi gate passed.")

    def _gate_xss_reflection_only(self, finding: Dict[str, Any], evidence: Dict[str, Any]) -> FirewallVerdict:
        """Rule 3: Plain string reflection is NOT confirmed XSS."""
        vuln_type = (finding.get("type") or finding.get("title") or "").upper()
        if "XSS" in vuln_type or "CROSS-SITE SCRIPTING" in vuln_type:
            dom_sink = evidence.get("dom_sink_verified", False)
            browser_executed = evidence.get("browser_execution_verified", False)
            unescaped_html = evidence.get("unescaped_context_verified", False)

            if not any([dom_sink, browser_executed, unescaped_html]):
                return FirewallVerdict(
                    decision=GateDecision.NEEDS_REVIEW,
                    rule_id="FP-XSS-001",
                    reason="Parameter reflected but lack of unescaped HTML/JavaScript sink or browser execution proof. Stored as candidate only.",
                    confidence_penalty=0.4,
                    recommended_state="CANDIDATE"
                )
        return FirewallVerdict(GateDecision.PASS, "FP-XSS-PASS", "XSS gate passed.")

    def _gate_idor_status_code_only(self, finding: Dict[str, Any], evidence: Dict[str, Any]) -> FirewallVerdict:
        """Rule 4: HTTP 200 OK is NOT confirmed IDOR without cross-identity ownership proof."""
        vuln_type = (finding.get("type") or finding.get("title") or "").upper()
        if "IDOR" in vuln_type or "BOLA" in vuln_type:
            multi_identity = evidence.get("cross_identity_tested", False)
            ownership_crossed = evidence.get("ownership_boundary_crossed", False)
            semantic_diff = evidence.get("semantic_content_confirmed", False)

            if not (multi_identity and ownership_crossed and semantic_diff):
                return FirewallVerdict(
                    decision=GateDecision.NEEDS_REVIEW,
                    rule_id="FP-IDOR-001",
                    reason="IDOR requires verified multi-identity object ownership boundary crossing (User A object accessed by User B). Stored as candidate.",
                    confidence_penalty=0.45,
                    recommended_state="CANDIDATE"
                )
        return FirewallVerdict(GateDecision.PASS, "FP-IDOR-PASS", "IDOR gate passed.")

    def _gate_cve_banner_match_only(self, finding: Dict[str, Any], evidence: Dict[str, Any]) -> FirewallVerdict:
        """Rule 5: Version string alone is NOT confirmed CVE."""
        cve_id = finding.get("cve_id") or finding.get("cve")
        if cve_id:
            affected_version_verified = evidence.get("affected_version_verified", False)
            exploitability_verified = evidence.get("exploitability_verified", False)
            active_endpoint_verified = evidence.get("active_endpoint_verified", False)

            if not affected_version_verified and not exploitability_verified:
                return FirewallVerdict(
                    decision=GateDecision.NEEDS_REVIEW,
                    rule_id="FP-CVE-001",
                    reason=f"CVE {cve_id} based on raw version banner without backport verification or exploitability proof. Marked as candidate.",
                    confidence_penalty=0.3,
                    recommended_state="CANDIDATE"
                )
        return FirewallVerdict(GateDecision.PASS, "FP-CVE-PASS", "CVE gate passed.")

    def _gate_nuclei_unverified_candidate(self, finding: Dict[str, Any], evidence: Dict[str, Any]) -> FirewallVerdict:
        """Rule 6: Nuclei match is candidate until validated."""
        source = (finding.get("source") or "").lower()
        if "nuclei" in source and not evidence.get("independent_validation_passed", False):
            return FirewallVerdict(
                decision=GateDecision.NEEDS_REVIEW,
                rule_id="FP-NUCLEI-001",
                reason="Nuclei scanner output requires independent validation proof before confirmation.",
                confidence_penalty=0.2,
                recommended_state="CANDIDATE"
            )
        return FirewallVerdict(GateDecision.PASS, "FP-NUCLEI-PASS", "Scanner verification passed.")

    def _gate_open_port_not_vulnerability(self, finding: Dict[str, Any], evidence: Dict[str, Any]) -> FirewallVerdict:
        """Rule 7: Standard open port (80, 443) is not a vulnerability."""
        vuln_type = (finding.get("type") or finding.get("title") or "").upper()
        if "PORT" in vuln_type and "OPEN" in vuln_type:
            port = int(finding.get("port") or evidence.get("port") or 0)
            if port in (80, 443):
                return FirewallVerdict(
                    decision=GateDecision.REJECTED,
                    rule_id="FP-PORT-001",
                    reason="Standard web ports 80/443 open is standard operational behavior, not a vulnerability finding.",
                    confidence_penalty=1.0,
                    recommended_state="REJECTED"
                )
        return FirewallVerdict(GateDecision.PASS, "FP-PORT-PASS", "Port gate passed.")

    def _gate_empty_or_missing_evidence(self, finding: Dict[str, Any], evidence: Dict[str, Any]) -> FirewallVerdict:
        """Rule 8: Missing evidence cannot be confirmed."""
        req = evidence.get("request") or finding.get("request")
        resp = evidence.get("response") or finding.get("response")
        evidence_level = finding.get("evidence_level") or evidence.get("evidence_level") or "E0"

        if not req and not resp and evidence_level in ("E3", "E4"):
            return FirewallVerdict(
                decision=GateDecision.REJECTED,
                rule_id="FP-EVID-001",
                reason="Finding claims high evidence level (E3/E4) but lacks raw HTTP request/response forensics.",
                confidence_penalty=0.6,
                recommended_state="NEEDS_REVIEW"
            )
        return FirewallVerdict(GateDecision.PASS, "FP-EVID-PASS", "Evidence presence verified.")


# Global Singleton Instance
false_positive_firewall = FalsePositiveFirewall()
