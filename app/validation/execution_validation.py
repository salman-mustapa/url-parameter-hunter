"""Controlled Execution Validation Subsystem (V8 §15).

Implements the Proof-of-Execution abstraction:
Candidate → Authorized Validator → Unique Harmless Canary → Expected Result → Structured Evidence.

Strict Safety Rules:
- Never execute destructive commands (rm, format, drop, shutdown)
- Never deploy malware or persistence mechanisms in production
- Always use randomized, non-destructive, unique cryptographic canaries
"""

from __future__ import annotations

import hashlib
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("validation.execution")


@dataclass
class ExecutionProof:
    canary_token: str
    expected_output: str
    target: str
    execution_context: str
    timestamp: str
    confirmed: bool
    evidence_data: Dict[str, Any] = field(default_factory=dict)


class ControlledExecutionValidator:
    """Validator for safely proving code/command execution via harmless canaries (V8 §15)."""

    @classmethod
    def generate_harmless_canary(cls, test_prefix: str = "bh_canary") -> Dict[str, str]:
        """Generates a randomized, harmless mathematical or string canary."""
        token = f"{test_prefix}_{uuid.uuid4().hex[:8]}"
        # Harmless mathematical proof: e.g. echo 84729174 + 19284719
        rand_a = int(time.time()) % 90000 + 10000
        rand_b = 84721
        expected_sum = str(rand_a + rand_b)

        return {
            "canary_token": token,
            "math_expression": f"{rand_a}+{rand_b}",
            "expected_math_result": expected_sum,
            "echo_payload": f"echo {token}",
            "expected_echo_result": token,
        }

    @classmethod
    def verify_canary_reflection(
        cls,
        response_body: str,
        canary_data: Dict[str, str],
        target_url: str,
    ) -> ExecutionProof:
        """Verifies if the harmless canary output was cleanly reflected in the target response."""
        echo_target = canary_data.get("expected_echo_result", "")
        math_target = canary_data.get("expected_math_result", "")

        confirmed = False
        context_found = "none"

        if echo_target and echo_target in response_body:
            confirmed = True
            context_found = f"Literal string canary reflection '{echo_target}'"
        elif math_target and math_target in response_body:
            confirmed = True
            context_found = f"Mathematical evaluation result '{math_target}'"

        now_utc = datetime.now(timezone.utc).isoformat()
        proof = ExecutionProof(
            canary_token=canary_data.get("canary_token", "unknown"),
            expected_output=echo_target or math_target,
            target=target_url,
            execution_context=context_found,
            timestamp=now_utc,
            confirmed=confirmed,
            evidence_data={
                "target": target_url,
                "verified_at": now_utc,
                "context": context_found,
                "proof_type": "harmless_canary_proof_of_execution",
            },
        )

        if confirmed:
            logger.info("Proof-of-Execution confirmed on %s (%s)", target_url, context_found)
        return proof


controlled_execution_validator = ControlledExecutionValidator()
