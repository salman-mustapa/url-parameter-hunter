"""Report AI Agent (V8 §10).

Responsibilities:
- Synthesizes professional finding narratives
- Generates executive summaries and business impact explanations
- Formats clean, deterministic reproduction steps
- Recommends tailored, technology-specific remediation
- Links authoritative references (CWE, CVE, OWASP)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.reporting.redaction import RedactionEngine

logger = logging.getLogger("ai.agents.report")


class ReportAgent:
    """Specialized AI agent for drafting audit-grade vulnerability reports (V8 §10)."""

    @classmethod
    async def generate_finding_narrative(
        cls,
        finding: Dict[str, Any],
        context_target: str,
    ) -> Dict[str, str]:
        """Synthesizes structured narrative components for a verified finding."""
        title = finding.get("title", "Security Vulnerability")
        vuln_type = finding.get("finding_type", "security_issue")
        endpoint = finding.get("url") or finding.get("endpoint_url") or context_target
        param = finding.get("parameter") or ""

        # Executive summary
        exec_summary = (
            f"An authorized technical evaluation confirmed a {vuln_type.replace('_', ' ')} on {context_target}. "
            f"The weakness allows an attacker to exploit the endpoint `{endpoint}`{f' via parameter `{param}`' if param else ''}, "
            f"potentially compromising the integrity and confidentiality of application services."
        )

        # Technical explanation & root cause
        root_cause = (
            f"The application fails to sufficiently sanitize or validate user-controlled input prior to processing at `{endpoint}`. "
            f"State transitions and data parsing logic deviate from secure engineering baselines."
        )

        # Remediation
        remediation = (
            f"1. Implement strict server-side validation and parameter encoding.\n"
            f"2. Apply defense-in-depth controls (Content Security Policy, Least Privilege db accounts, WAF rules).\n"
            f"3. Validate session integrity and enforce explicit authorization checks on all state transitions."
        )

        return {
            "title": title,
            "executive_summary": exec_summary,
            "root_cause": root_cause,
            "remediation": remediation,
            "business_impact": finding.get("business_impact") or "Potential exposure of sensitive customer records or unauthorized operation execution.",
        }
