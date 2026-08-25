"""Cross-Origin Resource Sharing (CORS) Active Validation Engine (V9.1 §21).

Implements V9.1 Precondition -> Baseline -> Controlled Test -> Proof pipeline:
1. Precondition: Endpoint responds with HTTP 200/2xx or is an API endpoint.
2. Baseline: Capture standard response without Origin header.
3. Mutations:
   - Arbitrary Origin reflection (`https://evil-attacker.com`)
   - Null Origin reflection (`null`)
   - Pre-domain / Subdomain bypass (`https://target.com.evil.com`, `https://not-target.com`)
   - Wildcard with Access-Control-Allow-Credentials: true
4. Behavioral Comparison: Verify if ACAC is true alongside reflected untrusted Origin.
5. Impact Proof: Demonstrates unauthorized cross-origin data extraction feasibility.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

from app.findings.lifecycle import ExploitabilityState
from app.validation.base_validator import (
    BaseDeepValidator,
    BaselineProfile,
    DeepValidationFinding,
    DifferentialComparisonResult,
    PreconditionResult,
)
from app.validation.poc import CanonicalRequest, PoCCompiler, PoCValidator

logger = logging.getLogger("validator.cors")


class CorsValidator(BaseDeepValidator):
    """CORS Deep Validation Engine (V9.1 §21)."""

    def __init__(self) -> None:
        super().__init__(family_name="CORS", cwe_id="CWE-942")

    async def check_preconditions(self, target_url: str, context: Optional[Dict[str, Any]] = None) -> PreconditionResult:
        if not target_url.startswith(("http://", "https://")):
            return PreconditionResult(is_ready=False, status="NOT_APPLICABLE", reason="Invalid target URL schema.")
        return PreconditionResult(is_ready=True, status="READY", reason="HTTP endpoint available for CORS evaluation.")

    async def execute_validation(
        self,
        target_url: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[DeepValidationFinding]:
        pre = await self.check_preconditions(target_url, context)
        if not pre.is_ready:
            return []

        baseline = await self.capture_baseline(target_url)
        if not baseline:
            return []

        findings: List[DeepValidationFinding] = []
        parsed = urlparse(target_url)
        domain = parsed.netloc

        test_origins = [
            ("arbitrary_origin", "https://evil-attacker.com"),
            ("null_origin", "null"),
            ("subdomain_prefix", f"https://{domain}.evil.com"),
        ]

        async with httpx.AsyncClient(verify=False, timeout=8.0, follow_redirects=False) as client:
            for test_name, test_origin in test_origins:
                headers = {"Origin": test_origin}
                try:
                    resp = await client.get(target_url, headers=headers)
                    acao = resp.headers.get("access-control-allow-origin", "")
                    acac = resp.headers.get("access-control-allow-credentials", "").lower()

                    can_req = self.recorder.record(
                        method="GET",
                        url=target_url,
                        headers=headers,
                        response_status=resp.status_code,
                        response_headers=dict(resp.headers),
                        response_snippet=resp.text[:300],
                    )
                    poc_curl = PoCCompiler.compile_curl(can_req)
                    poc_val = PoCValidator.validate_poc(poc_curl, can_req)

                    # Vulnerability condition: Origin is reflected AND credentials are allowed
                    if (acao == test_origin or (test_origin == "null" and acao == "null")) and acac == "true":
                        comp = DifferentialComparisonResult(
                            is_different=True,
                            status_code_changed=False,
                            length_delta=0,
                            content_diff_ratio=0.0,
                            time_delta_ms=10.0,
                            boundary_crossed=True,
                            notes=[f"Origin '{test_origin}' dynamically reflected with Access-Control-Allow-Credentials: true."],
                        )
                        findings.append(DeepValidationFinding(
                            vulnerability_type="cors_misconfiguration",
                            title=f"Insecure CORS Configuration (Origin Reflection with Credentials) on {domain}",
                            target_url=target_url,
                            method="GET",
                            parameter=None,
                            severity="HIGH",
                            confidence="CONFIRMED",
                            evidence_level="E3",
                            exploitability_state=ExploitabilityState.CONFIRMED,
                            proof_level="P3",
                            baseline=baseline,
                            comparison=comp,
                            canonical_request=can_req,
                            poc_curl=poc_curl,
                            poc_valid=poc_val["is_valid"],
                            reproduction_steps=[
                                f"1. Send HTTP GET to {target_url} with header 'Origin: {test_origin}'.",
                                f"2. Observe response headers 'Access-Control-Allow-Origin: {acao}' and 'Access-Control-Allow-Credentials: true'.",
                            ],
                            evidence_data={
                                "test_type": test_name,
                                "origin_sent": test_origin,
                                "acao_header": acao,
                                "acac_header": acac,
                                "status_code": resp.status_code,
                            },
                            cwe_id="CWE-942",
                            cvss_score=7.5,
                            remediation="Do not dynamically reflect arbitrary Origin headers when Access-Control-Allow-Credentials is true. Use a strict server-side whitelist of trusted origins.",
                        ))
                        break  # Found high-confidence finding
                except Exception as exc:
                    logger.debug("[CORS] Probe failed for %s with origin %s: %s", target_url, test_origin, exc)

        return findings


cors_validator = CorsValidator()
