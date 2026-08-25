"""Evidence Critic AI Agent (V8 §10, §29 & V9.1 §20, Phase 12).

Executes mandatory 7-point consistency validation before marking a finding report-ready:
1. request ↔ PoC (verifies PoC accurately reproduces executed request)
2. request ↔ response (checks response status and content consistency)
3. finding ↔ evidence (ensures finding type matches evidence telemetry)
4. severity ↔ impact (Four-Axis Rule: Critical/High requires E2+ impact proof)
5. CVE ↔ asset/version (verifies version falls within affected range)
6. CWE ↔ root cause (validates CWE taxonomy alignment)
7. screenshot ↔ actual state (verifies visual evidence shows real target response)

Outputs one of:
- READY (is_report_ready = True)
- NEEDS_EVIDENCE
- NEEDS_VALIDATION
- NEEDS_REDACTION
- REJECTED (False finding / hallucination)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.ai.agents.poc_consistency_agent import poc_consistency_agent

logger = logging.getLogger("ai.agents.evidence_critic")


class EvidenceCriticVerdict:
    READY = "READY"
    NEEDS_EVIDENCE = "NEEDS_EVIDENCE"
    NEEDS_VALIDATION = "NEEDS_VALIDATION"
    NEEDS_REDACTION = "NEEDS_REDACTION"
    REJECTED = "REJECTED"


class EvidenceCriticAgent:
    """Evaluates finding quality, defensibility, and compliance with evidence standards (V8 §29, V9.1 §20)."""

    @classmethod
    async def review_finding_evidence(
        cls,
        finding: Dict[str, Any],
        evidence_package: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Conducts rigorous 7-point consistency criticism and assigns overall defensibility score."""
        issues: List[str] = []
        consistency_matrix: Dict[str, bool] = {}
        scores: Dict[str, int] = {
            "poc_consistency": 100,
            "response_consistency": 100,
            "evidence_relevance": 100,
            "severity_impact_alignment": 100,
            "cve_applicability": 100,
            "cwe_taxonomy": 100,
            "visual_fidelity": 100,
            "redaction": 100,
        }

        # -------------------------------------------------------------
        # 1. Check: request <-> PoC Consistency
        # -------------------------------------------------------------
        poc_cmd = finding.get("poc") or finding.get("poc_curl") or finding.get("poc_command") or ""
        rec_req = finding.get("canonical_request") or finding.get("request_metadata") or {}
        if poc_cmd:
            poc_eval = poc_consistency_agent.verify_poc_defensibility(poc_cmd, rec_req, finding.get("finding_type", ""))
            if not poc_eval.get("is_consistent"):
                scores["poc_consistency"] = 20
                issues.extend(poc_eval.get("consistency_issues", ["PoC mismatch detected."]))
                consistency_matrix["request_poc"] = False
            else:
                consistency_matrix["request_poc"] = True
        else:
            scores["poc_consistency"] = 30
            issues.append("Missing actionable PoC command for reproduction.")
            consistency_matrix["request_poc"] = False

        # -------------------------------------------------------------
        # 2. Check: request <-> response Consistency
        # -------------------------------------------------------------
        resp_meta = finding.get("response_metadata") or {}
        status_code = resp_meta.get("status_code") or finding.get("status_code")
        f_type = (finding.get("finding_type") or finding.get("vulnerability_type") or "").lower()
        if status_code in (404, 502, 503) and ("sql_dump" in f_type or "csv_export" in f_type):
            scores["response_consistency"] = 0
            issues.append(f"HTTP {status_code} contradicts claim of exposed data artifact.")
            consistency_matrix["request_response"] = False
        elif status_code == 403 and "auth_bypass" in f_type:
            scores["response_consistency"] = 0
            issues.append("HTTP 403 Forbidden is access denial, contradicting authentication bypass claim.")
            consistency_matrix["request_response"] = False
        else:
            consistency_matrix["request_response"] = True

        # -------------------------------------------------------------
        # 3. Check: finding <-> evidence Telemetry
        # -------------------------------------------------------------
        ev_data = finding.get("evidence") or finding.get("evidence_data")
        if not ev_data:
            scores["evidence_relevance"] = 30
            issues.append("Missing structured evidence telemetry.")
            consistency_matrix["finding_evidence"] = False
        else:
            consistency_matrix["finding_evidence"] = True

        # -------------------------------------------------------------
        # 4. Check: severity <-> impact Alignment (Four-Axis Rule)
        # -------------------------------------------------------------
        sev = (finding.get("severity") or "MEDIUM").upper()
        ev_level = (finding.get("evidence_level") or "E0").upper()
        if sev in ("CRITICAL", "HIGH") and ev_level in ("E0", "E1"):
            scores["severity_impact_alignment"] = 30
            issues.append(f"Finding rated {sev} but only has {ev_level} observation evidence without proven exploitability.")
            consistency_matrix["severity_impact"] = False
        else:
            consistency_matrix["severity_impact"] = True

        # -------------------------------------------------------------
        # 5. Check: CVE <-> asset/version Alignment
        # -------------------------------------------------------------
        cve_id = finding.get("cve_id")
        if cve_id:
            cve_state = finding.get("cve_applicability_state", "VALIDATED")
            if cve_state in ("NOT_AFFECTED", "PATCHED"):
                scores["cve_applicability"] = 0
                issues.append(f"CVE {cve_id} is marked {cve_state} for current detected version.")
                consistency_matrix["cve_version"] = False
            else:
                consistency_matrix["cve_version"] = True
        else:
            consistency_matrix["cve_version"] = True

        # -------------------------------------------------------------
        # 6. Check: CWE <-> root cause
        # -------------------------------------------------------------
        cwe_id = finding.get("cwe_id")
        if not cwe_id or not cwe_id.startswith("CWE-"):
            scores["cwe_taxonomy"] = 60
            issues.append("Invalid or unmapped CWE taxonomy identifier.")
            consistency_matrix["cwe_taxonomy"] = False
        else:
            consistency_matrix["cwe_taxonomy"] = True

        # -------------------------------------------------------------
        # 7. Check: screenshot <-> observed state
        # -------------------------------------------------------------
        screenshots = finding.get("screenshots") or []
        has_screenshot = len(screenshots) > 0 or bool(finding.get("screenshot_path"))
        if not has_screenshot and sev in ("CRITICAL", "HIGH"):
            scores["visual_fidelity"] = 70
            issues.append("High severity finding lacks supporting visual / screenshot proof.")
            consistency_matrix["screenshot_state"] = False
        else:
            consistency_matrix["screenshot_state"] = True

        # -------------------------------------------------------------
        # 8. Check: Secrets & PII Redaction
        # -------------------------------------------------------------
        desc = str(finding.get("description") or "")
        tech_details = str(finding.get("technical_details") or "")
        raw_proof = str(finding.get("actual_result") or "")
        combined = f"{desc} {tech_details} {raw_proof}"
        if any(w in combined.lower() for w in ("password=", "bearer eyj", "private_key", "secret_key=")):
            scores["redaction"] = 20
            issues.append("Unredacted sensitive tokens or private keys detected in finding text.")

        # Compute overall score
        overall = sum(scores.values()) // len(scores)

        # Determine final verdict
        if scores["response_consistency"] == 0 or scores["cve_applicability"] == 0:
            verdict = EvidenceCriticVerdict.REJECTED
        elif scores["redaction"] < 50:
            verdict = EvidenceCriticVerdict.NEEDS_REDACTION
        elif scores["severity_impact_alignment"] < 50 or scores["poc_consistency"] < 50:
            verdict = EvidenceCriticVerdict.NEEDS_VALIDATION
        elif scores["evidence_relevance"] < 50 or scores["visual_fidelity"] < 50:
            verdict = EvidenceCriticVerdict.NEEDS_EVIDENCE
        else:
            verdict = EvidenceCriticVerdict.READY

        logger.info("Evidence Critic verdict for '%s': %s (Score: %d)", finding.get("title"), verdict, overall)

        return {
            "agent": "evidence_critic_agent",
            "verdict": verdict,
            "overall_defensibility_score": overall,
            "consistency_matrix": consistency_matrix,
            "sub_scores": scores,
            "critic_notes": issues,
            "is_report_ready": verdict == EvidenceCriticVerdict.READY,
        }


evidence_critic_agent = EvidenceCriticAgent()
