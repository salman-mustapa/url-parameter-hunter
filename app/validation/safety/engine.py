"""Safety Engine (V10 Evidence-Driven Validation Architecture).

Interprets and enforces safety policies during automated validation probing.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, Optional

from app.validation.safety.policy import SafetyPolicy

logger = logging.getLogger("validation.safety")


class SafetyEngine:
    """Enforces execution safety, rate limits, and non-destructive policies."""

    def __init__(self, policy: Optional[SafetyPolicy] = None) -> None:
        self.policy = policy or SafetyPolicy()
        self._target_request_counts: Dict[str, int] = {}
        self._target_error_counts: Dict[str, int] = {}
        self._target_start_times: Dict[str, float] = {}

    def start_validation_session(self, target_url: str) -> None:
        """Initialize session tracking for a specific validation target."""
        self._target_request_counts[target_url] = 0
        self._target_error_counts[target_url] = 0
        self._target_start_times[target_url] = time.time()

    def check_can_proceed(self, target_url: str, proposed_payload_len: int = 0) -> Tuple[bool, str]:
        """Verify whether an outbound probe complies with safety limits."""
        # 1. Payload size check
        if proposed_payload_len > self.policy.max_payload_size_bytes:
            return False, f"Payload size ({proposed_payload_len} bytes) exceeds safety limit ({self.policy.max_payload_size_bytes} bytes)."

        # 2. Duration check
        start_time = self._target_start_times.get(target_url, time.time())
        elapsed = time.time() - start_time
        if elapsed > self.policy.max_duration_seconds:
            return False, f"Validation session exceeded max duration ({elapsed:.1f}s > {self.policy.max_duration_seconds}s)."

        # 3. Request count check
        req_count = self._target_request_counts.get(target_url, 0)
        if req_count >= self.policy.max_requests_per_target:
            return False, f"Target request limit reached ({req_count}/{self.policy.max_requests_per_target})."

        # 4. Error threshold check
        err_count = self._target_error_counts.get(target_url, 0)
        if err_count >= self.policy.abort_threshold_errors:
            return False, f"Target error threshold reached ({err_count} consecutive network/server errors). Aborting."

        return True, "OK"

    def record_request(self, target_url: str, is_error: bool = False) -> None:
        """Track dispatched request and error state."""
        self._target_request_counts[target_url] = self._target_request_counts.get(target_url, 0) + 1
        if is_error:
            self._target_error_counts[target_url] = self._target_error_counts.get(target_url, 0) + 1
        else:
            self._target_error_counts[target_url] = 0  # Reset consecutive error count on success

    def validate_command_safety(self, command_str: str) -> bool:
        """Verify command string is non-destructive."""
        return self.policy.is_safe_command(command_str)


from typing import Tuple

safety_engine = SafetyEngine()
