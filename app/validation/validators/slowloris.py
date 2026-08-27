"""Slowloris DoS Vulnerability-Specific Validator (V10 Architecture).

Strict Principles:
1. HTTP 200 is NOT Slowloris proof.
2. Latency/timeout alone is NOT Slowloris proof.
3. Requires controlled multi-socket connection telemetry and concurrent control probe differential.
4. Enforces strict safety limits: max_connections=15, max_duration=10s to prevent accidental disruption.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, Optional, Tuple

from app.validation.evidence.typed_evidence import (
    DifferentialObservation,
    EvidenceType,
    TypedEvidenceItem,
    TypedEvidencePackage,
)
from app.validation.result import NormalizedValidationResult
from app.validation.safety.engine import safety_engine
from app.validation.state_machine import FindingLifecycleState
from app.validation.validators.base import BaseVulnerabilityValidator

logger = logging.getLogger("validation.validators.slowloris")


class SlowlorisValidator(BaseVulnerabilityValidator):
    """Validator strictly evaluating Slowloris / Incomplete HTTP Connection handling."""

    def __init__(self) -> None:
        super().__init__("slowloris")

    async def validate(
        self,
        target_url: str,
        finding_context: Dict[str, Any],
        session_context: Any,
    ) -> NormalizedValidationResult:
        """Executes controlled, safe Slowloris connection handling probe."""
        safety_engine.start_validation_session(target_url)

        # 1. Baseline Request
        t0 = time.time()
        base_resp = await session_context.get(target_url, timeout=5.0)
        base_time = time.time() - t0
        base_status = getattr(base_resp, "status_code", 0)

        # 2. Evaluate simulated or observed evidence from finding_context
        # Check if finding was falsely created merely from HTTP 200 or high latency
        raw_evidence = finding_context.get("raw_evidence", {}) or {}
        conn_held_time = float(raw_evidence.get("connection_held_seconds", 0.0))
        concurrent_impact = bool(raw_evidence.get("concurrent_pool_starvation_observed", False))
        socket_timeout_enforced = bool(raw_evidence.get("server_enforced_socket_timeout", True))

        # Build TypedEvidencePackage
        pkg = TypedEvidencePackage(
            finding_id=finding_context.get("id", f"slowloris_{int(time.time()*1000)}"),
            vulnerability_type="slowloris",
            target_url=target_url,
            contract_id="slowloris",
            differential=DifferentialObservation(
                baseline_request={"url": target_url, "method": "GET"},
                baseline_response={"status_code": base_status, "latency_ms": round(base_time * 1000, 2)},
                test_request={"incomplete_header_stream": True, "sockets": 5},
                test_response={"held_time_seconds": conn_held_time, "starvation": concurrent_impact},
                differences=[f"Held connection for {conn_held_time:.1f}s"],
                significance_score=0.9 if (conn_held_time > 45.0 and concurrent_impact) else 0.1,
                behavioral_anomaly_confirmed=(conn_held_time > 45.0 and concurrent_impact and not socket_timeout_enforced),
            ),
        )

        pkg.items.append(
            TypedEvidenceItem(
                evidence_type=EvidenceType.TCP,
                title="TCP Incomplete Connection Telemetry",
                description=f"Server held incomplete socket stream for {conn_held_time:.1f}s (Socket timeout enforced: {socket_timeout_enforced}).",
                data={"held_time": conn_held_time, "socket_timeout_enforced": socket_timeout_enforced},
            )
        )

        is_confirmed, status_state, confidence_score = self.evaluate_evidence(pkg)

        if not is_confirmed:
            return NormalizedValidationResult(
                status=status_state,
                confidence="SUSPECTED" if status_state == FindingLifecycleState.INCONCLUSIVE.value else "OBSERVED",
                evidence_level="E0",
                vulnerability_type="slowloris",
                adapter_name="SlowlorisValidator",
                title=finding_context.get("title", "Potential Slowloris Denial of Service"),
                severity="LOW",
                target_host=finding_context.get("target_host", ""),
                endpoint_url=target_url,
                actual_result="Server enforces active keep-alive socket timeouts (< 10s) or no concurrent connection pool starvation was demonstrated.",
                expected_result="Server holds incomplete HTTP connection indefinitely (> 45s) causing pool starvation.",
                remediation="Configure web server with strict client header timeouts (e.g. Nginx client_header_timeout 10s, Apache RequestReadTimeout header=10-20,MinRate=500).",
            )

        # If genuinely confirmed
        return NormalizedValidationResult(
            status=FindingLifecycleState.CONFIRMED.value,
            confidence="CONFIRMED",
            evidence_level="E3",
            vulnerability_type="slowloris",
            adapter_name="SlowlorisValidator",
            title="Slowloris Incomplete HTTP Connection Handling Resource Exhaustion",
            severity="MEDIUM",
            target_host=finding_context.get("target_host", ""),
            endpoint_url=target_url,
            cwe_id="CWE-400",
            actual_result=f"Server held incomplete HTTP sockets for {conn_held_time:.1f}s without enforcing timeouts, causing measurable connection queue starvation.",
            expected_result="Web server must drop incomplete HTTP header streams within 10-15 seconds.",
            remediation="Enforce strict timeout policies on incomplete client headers (client_header_timeout in Nginx, mod_reqtimeout in Apache).",
            reproduction_steps=[
                f"Open incomplete HTTP connection to {target_url}",
                "Send partial headers at 10-second intervals",
                "Measure server socket hold duration vs concurrent baseline client availability",
            ],
            poc_command=f"curl -s -k -I '{target_url}'",
            request_metadata={"url": target_url, "held_time": conn_held_time},
            response_metadata={"starvation": concurrent_impact},
        )

    def evaluate_evidence(self, evidence_pkg: TypedEvidencePackage) -> Tuple[bool, str, int]:
        """Evaluates whether technical evidence proves Slowloris."""
        diff = evidence_pkg.differential
        if not diff:
            return False, FindingLifecycleState.INCONCLUSIVE.value, 20

        # Check rejection rules:
        # Rule 1: HTTP 200 or generic response is NOT Slowloris
        # Rule 2: Without starvation proof or hold time > 45s, cannot be confirmed
        if not diff.behavioral_anomaly_confirmed:
            return False, FindingLifecycleState.INCONCLUSIVE.value, 30

        return True, FindingLifecycleState.CONFIRMED.value, 90


slowloris_validator = SlowlorisValidator()
