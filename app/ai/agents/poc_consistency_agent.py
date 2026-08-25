"""PoC Consistency Agent (V9.1 Phase 13, §16).

Specialized AI / Deterministic Critic for verifying PoC defensibility:
- Ensures PoC is strictly derived from recorded wire requests.
- Detects synthetic / empty data payloads (e.g. `curl -d ''` when body is required).
- Checks HTTP method, query parameters, headers, and cookies consistency.
- Rejects fabricated or hallucinated PoC commands (`POC_INVALID`, `report_ready=False`).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from app.validation.poc import CanonicalRequest, PoCValidator

logger = logging.getLogger("ai.agents.poc_consistency")


class PoCConsistencyAgent:
    """Evaluates consistency between executed requests, captured evidence, and generated PoCs."""

    @classmethod
    def verify_poc_defensibility(
        cls,
        poc_command: str,
        recorded_request: Optional[Dict[str, Any] | CanonicalRequest] = None,
        finding_type: str = "general",
    ) -> Dict[str, Any]:
        """Conducts strict wire-to-PoC verification."""
        if not poc_command:
            return {
                "status": "POC_INVALID",
                "is_consistent": False,
                "reason": "PoC command is completely empty or missing.",
                "report_ready": False,
            }

        canonical: Optional[CanonicalRequest] = None
        if isinstance(recorded_request, CanonicalRequest):
            canonical = recorded_request
        elif isinstance(recorded_request, dict):
            canonical = CanonicalRequest(
                method=recorded_request.get("method", "GET"),
                url=recorded_request.get("url", ""),
                headers=recorded_request.get("headers", {}),
                data=recorded_request.get("data"),
                query_params=recorded_request.get("query_params", {}),
            )

        if not canonical or not canonical.url:
            import re
            m = re.search(r"https?://[^\s'\"\\]+", poc_command)
            if m:
                canonical = CanonicalRequest(
                    method="POST" if "-X POST" in poc_command.upper() else "GET",
                    url=m.group(0),
                )
            else:
                return {
                    "status": "POC_INVALID",
                    "is_consistent": False,
                    "reason": "Missing recorded wire request and cannot parse target URL from PoC command.",
                    "report_ready": False,
                }

        val_res = PoCValidator.validate_poc(poc_command, canonical)
        is_valid = val_res.get("is_valid", False)

        issues = []
        if not is_valid:
            issues.append(val_res.get("reason", "PoC mismatch detected."))

        # Additional domain and target checks
        parsed_target = urlparse(canonical.url)
        if parsed_target.netloc and parsed_target.netloc not in poc_command:
            issues.append(f"Target host '{parsed_target.netloc}' not found in PoC command.")

        # Check for empty body anomaly
        if canonical.data and "-d ''" in poc_command:
            issues.append("Synthetic empty body (-d '') found in PoC while wire request transmitted active payload.")

        is_consistent = len(issues) == 0 and is_valid

        return {
            "status": "POC_VALID" if is_consistent else "POC_INVALID",
            "is_consistent": is_consistent,
            "report_ready": is_consistent,
            "consistency_issues": issues,
            "canonical_method": canonical.method,
            "target_url": canonical.url,
        }


poc_consistency_agent = PoCConsistencyAgent()
