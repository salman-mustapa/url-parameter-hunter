"""Disclosure drafts derived from stored findings and explicit chain records."""
from __future__ import annotations

import json
from typing import Any, Dict, Optional

from app.reporting.engine import ReportEngine
from app.reporting.redaction import RedactionEngine
from app.validation.result import NormalizedValidationResult


class BugBountyReportGenerator:
    @classmethod
    def generate_finding_report(cls, finding: NormalizedValidationResult, researcher_alias="BugHunter-AI", screenshot_path=None):
        data = finding.to_dict()
        data.update({"asset_hostname": finding.target_host, "location": finding.endpoint_url,
                     "finding_type": finding.vulnerability_type, "poc": finding.poc_command,
                     "impact": finding.business_impact,
                     "evidence": {"request_headers": (finding.request_metadata or {}).get("headers"),
                                  "method": (finding.request_metadata or {}).get("method"),
                                  "request_body": (finding.request_metadata or {}).get("body"),
                                  "response_headers": (finding.response_metadata or {}).get("headers"),
                                  "response_status": (finding.response_metadata or {}).get("status_code"),
                                  "response_body": (finding.response_metadata or {}).get("body"),
                                  "observations": finding.observations}})
        return ReportEngine.generate_bug_bounty_markdown(data, finding.target_host)

    @classmethod
    def generate_chained_attack_report(cls, target: str, chain_candidate: Optional[Any] = None,
                                      researcher_alias="BugHunter-AI", custom_details: Optional[Dict[str, Any]] = None):
        # A planner candidate is a hypothesis, not evidence of successful execution.
        details = chain_candidate.to_dict() if chain_candidate else {"steps": [], "observations": custom_details or {}}
        details = RedactionEngine.redact_dict(details)
        lines = ["# Autonomous Multi-Stage Exploit Chain - Review Draft", "", f"Target: `{target}`", "",
                 "Status: HYPOTHESIS / REQUIRES VALIDATION. Planner preconditions and feasibility scores do not prove execution or impact.",
                 "No CVSS score, successful login, upload execution, or data compromise is inferred.", "",
                 "## Recorded Chain Steps", ""]
        graph = ["graph TD"]
        for index, step in enumerate(details.get("steps", []), 1):
            lines.extend([f"### Stage {index}: {step.get('stage', 'Not recorded')}",
                          f"Observation: {step.get('source_observation', 'Not recorded')}",
                          f"Target: {step.get('target_node', 'Not recorded')}",
                          f"Planner precondition met: {step.get('precondition_met', False)} (not execution proof)",
                          "```json", json.dumps(step.get("details", {}), indent=2), "```", ""])
            graph.append(f'  N{index}["Stage {index} - requires review"]')
            if index > 1:
                graph.append(f"  N{index-1} --> N{index}")
        if not details.get("steps"):
            lines.extend(["No executed chain steps have been supplied.", "```json", json.dumps(details.get("observations", {}), indent=2), "```"])
        lines.extend(["", "## Planner Structure", "```mermaid", "\n".join(graph), "```", "",
                      "## Remediation & Validation Follow-up",
                      "Review each affected component, required test identity and recorded request/response. Retest only under explicit authorization."])
        return "\n".join(lines)


bug_bounty_generator = BugBountyReportGenerator()
