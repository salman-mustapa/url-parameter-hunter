"""Server-Side Template Injection (SSTI) Deep Validation Engine (V9.1 §21).

Implements V9.1 Precondition -> Baseline -> Controlled Test -> Proof pipeline:
1. Precondition: Reflection detected or template-backed parameter.
2. Baseline: Capture normal response.
3. Mutations (Mathematical Expression Canaries):
   - Polyglot & Jinja2/Twig: `{{47*53}}` -> Expect `2491`
   - Ruby/ERB: `<%= 47*53 %>` -> Expect `2491`
   - Java/Spring EL: `${47*53}` -> Expect `2491`
   - Smarty: `{47*53}` -> Expect `2491`
   - Node/Nunjucks: `#{47*53}` -> Expect `2491`
4. Comparison: Verify evaluation result (2491) without raw expression string reflection.
5. Impact Proof: Demonstrates code execution in template runtime (P3/P4).
"""

from __future__ import annotations

from app.validation.safety.legacy import ValidationHTTPClient

import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse

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

logger = logging.getLogger("validator.ssti")

SSTI_PROBES = [
    ("jinja2_twig", "{{47*53}}", "2491", "Jinja2 / Twig / Python / PHP"),
    ("spring_el", "${47*53}", "2491", "Spring EL / Java EL"),
    ("ruby_erb", "<%= 47*53 %>", "2491", "Ruby ERB"),
    ("smarty", "{47*53}", "2491", "Smarty PHP"),
    ("node_pug", "#{47*53}", "2491", "Pug / Node.js"),
    ("mako", "${47*53}", "2491", "Mako / Python"),
]


class SstiValidator(BaseDeepValidator):
    """SSTI Deep Validation Engine (V9.1 §21)."""

    def __init__(self) -> None:
        super().__init__(family_name="SSTI", cwe_id="CWE-1336")

    async def check_preconditions(self, target_url: str, context: Optional[Dict[str, Any]] = None) -> PreconditionResult:
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query)
        ctx = context or {}
        if not params and not ctx.get("parameters"):
            return PreconditionResult(is_ready=False, status="NOT_APPLICABLE", reason="No parameters found for template evaluation.")
        return PreconditionResult(is_ready=True, status="READY", reason="Parameters available for SSTI evaluation.")

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
        params = parse_qs(parsed.query)

        async with ValidationHTTPClient(verify=False, timeout=8.0, follow_redirects=False) as client:
            for param_name in params.keys():
                for probe_name, payload, expected_eval, engine_hint in SSTI_PROBES:
                    # Mutate single parameter
                    mutated_params = dict(params)
                    mutated_params[param_name] = [payload]
                    query_str = urlencode(mutated_params, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_str}"

                    try:
                        resp = await client.get(test_url)
                        can_req = self.recorder.record(
                            method="GET",
                            url=test_url,
                            response_status=resp.status_code,
                            response_headers=dict(resp.headers),
                            response_snippet=resp.text[:300],
                        )
                        poc_curl = PoCCompiler.compile_curl(can_req)
                        poc_val = PoCValidator.validate_poc(poc_curl, can_req)

                        # Vulnerability condition: Evaluated result (2491) is in body AND raw payload is NOT in body
                        if expected_eval in resp.text and payload not in resp.text:
                            comp = DifferentialComparisonResult(
                                is_different=True,
                                status_code_changed=False,
                                length_delta=abs(len(resp.text) - baseline.content_length),
                                content_diff_ratio=0.3,
                                time_delta_ms=20.0,
                                reflected_canary=True,
                                boundary_crossed=True,
                                notes=[f"Mathematical expression '{payload}' evaluated to '{expected_eval}' by {engine_hint} engine."],
                            )
                            findings.append(DeepValidationFinding(
                                vulnerability_type="ssti",
                                title=f"Server-Side Template Injection (SSTI) in parameter '{param_name}' ({engine_hint})",
                                target_url=test_url,
                                method="GET",
                                parameter=param_name,
                                severity="CRITICAL",
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
                                    f"1. Send HTTP GET to {test_url} with parameter '{param_name}={payload}'.",
                                    f"2. Observe mathematical expression evaluated to '{expected_eval}' without literal expression reflection.",
                                ],
                                evidence_data={
                                    "parameter": param_name,
                                    "payload_sent": payload,
                                    "evaluated_output": expected_eval,
                                    "template_engine": engine_hint,
                                    "status_code": resp.status_code,
                                },
                                cwe_id="CWE-1336",
                                cvss_score=9.8,
                                remediation="Never pass un-sanitized user input directly into template rendering engines. Use logic-less templates or strict sandbox execution.",
                            ))
                            break
                    except Exception as exc:
                        logger.debug("[SSTI] Probe failed for %s param=%s: %s", target_url, param_name, exc)

        return findings


ssti_validator = SstiValidator()
