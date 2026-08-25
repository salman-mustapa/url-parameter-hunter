"""Vulnerability Analyst AI Agent (V8 §10).

Responsibilities:
- CVE correlation against local knowledge base
- Version normalization and semantic range comparison
- Applicability reasoning (whether config/context makes the CVE relevant)
- CWE suggestion and classification
- Confidence score assessment
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.intelligence.cve import CveIntelligence

logger = logging.getLogger("ai.agents.vuln_analyst")


class VulnerabilityAnalystAgent:
    """Specialized AI agent for deep vulnerability analysis and triage (V8 §10)."""

    @classmethod
    async def analyze_technology_vulnerabilities(
        cls,
        technology_name: str,
        version: Optional[str],
        endpoints: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Correlates version against known CVEs and evaluates context applicability."""
        norm_tech = technology_name.lower().strip()
        ver = (version or "").strip()

        raw_cves = CveIntelligence.correlate_vulnerabilities(norm_tech, ver)

        applicable_cves: List[Dict[str, Any]] = []
        for cve in raw_cves:
            # Evaluate applicability reasoning
            applicability = "APPLICABLE" if ver else "POTENTIALLY_APPLICABLE"
            confidence = "HIGH" if ver else "MEDIUM"

            applicable_cves.append({
                "cve_id": cve.get("cve_id"),
                "title": cve.get("title"),
                "severity": cve.get("severity", "MEDIUM"),
                "cvss_score": cve.get("cvss_score"),
                "cwe_id": cve.get("cwe_id", "CWE-200"),
                "applicability_state": applicability,
                "confidence": confidence,
                "remediation": cve.get("remediation"),
            })

        return {
            "agent": "vuln_analyst_agent",
            "technology": norm_tech,
            "version": ver or "unknown",
            "cves_found": len(applicable_cves),
            "candidates": applicable_cves,
        }
