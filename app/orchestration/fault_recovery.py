"""Fault Recovery, Worker Heartbeat & Dead Letter Queue (DLQ) (V13 §19, §20, §22, §23, §52).

Ensures NO PERMANENTLY STUCK JOB:
- Worker Heartbeat Tracker (Records heartbeat every 5s; triggers STALE state after 30s).
- Crash Recovery: Automatically requeues orphaned tasks to available workers.
- Error Classifier: Distinguishes TRANSIENT errors (retry with backoff) vs PERMANENT errors.
- Dead Letter Queue (DLQ): Captures tasks exceeding max_attempts to prevent infinite loops.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("orchestration.fault_recovery")


class ErrorCategory(str, Enum):
    TRANSIENT = "transient"  # Network glitch, 503, AI rate limit, timeout -> Retry with backoff
    PERMANENT = "permanent"  # Scope violation, invalid target, 404 handler -> Fail immediately
    UNKNOWN = "unknown"


@dataclass
class WorkerHeartbeat:
    worker_id: str
    task_id: str
    last_seen: float = field(default_factory=time.time)
    progress_pct: float = 0.0


@dataclass
class DeadLetterEntry:
    entry_id: str
    task_id: str
    scan_id: str
    tenant_id: str
    task_type: str
    target: str
    worker_id: str
    attempts: int
    last_error: str
    timestamp: float = field(default_factory=time.time)


class FaultRecoveryEngine:
    """Monitors worker heartbeats and guarantees recovery of failed / abandoned tasks."""

    def __init__(
        self,
        heartbeat_timeout_seconds: float = 30.0,
        max_task_attempts: int = 3,
    ) -> None:
        self.heartbeat_timeout_seconds = heartbeat_timeout_seconds
        self.max_task_attempts = max_task_attempts
        self._heartbeats: Dict[str, WorkerHeartbeat] = {}  # worker_id -> WorkerHeartbeat
        self._dead_letter_queue: List[DeadLetterEntry] = []
        self._task_attempts: Dict[str, int] = {}  # task_id -> count
        self._lock = asyncio.Lock()

    def record_heartbeat(self, worker_id: str, task_id: str, progress_pct: float = 0.0) -> None:
        """Called periodically by running workers."""
        self._heartbeats[worker_id] = WorkerHeartbeat(
            worker_id=worker_id,
            task_id=task_id,
            last_seen=time.time(),
            progress_pct=progress_pct,
        )

    def classify_error(self, error_str: str) -> ErrorCategory:
        """Classifies error into TRANSIENT or PERMANENT."""
        err_lower = error_str.lower()
        permanent_indicators = [
            "out of scope",
            "forbidden target",
            "invalid hostname",
            "unsupported protocol",
            "capability blocked",
        ]
        if any(p in err_lower for p in permanent_indicators):
            return ErrorCategory.PERMANENT
        return ErrorCategory.TRANSIENT

    async def scan_and_recover_stale_tasks(self) -> List[str]:
        """Detects dead workers and returns list of recovered task IDs."""
        now = time.time()
        recovered_task_ids: List[str] = []

        async with self._lock:
            for worker_id, hb in list(self._heartbeats.items()):
                idle_time = now - hb.last_seen
                if idle_time > self.heartbeat_timeout_seconds:
                    logger.warning(
                        "Worker %s timed out (idle %.1fs > %.1fs). Recovering task %s.",
                        worker_id, idle_time, self.heartbeat_timeout_seconds, hb.task_id
                    )
                    recovered_task_ids.append(hb.task_id)
                    del self._heartbeats[worker_id]

        return recovered_task_ids

    async def handle_task_failure(
        self,
        task_id: str,
        scan_id: str,
        tenant_id: str,
        task_type: str,
        target: str,
        worker_id: str,
        error_message: str,
    ) -> Dict[str, Any]:
        """Evaluates whether to retry or send to Dead Letter Queue."""
        category = self.classify_error(error_message)

        async with self._lock:
            current_attempts = self._task_attempts.get(task_id, 0) + 1
            self._task_attempts[task_id] = current_attempts

            # If permanent error or exceeded max attempts -> send to DLQ
            if category == ErrorCategory.PERMANENT or current_attempts >= self.max_task_attempts:
                dlq_id = f"dlq_{int(time.time()*1000)}_{len(self._dead_letter_queue)}"
                dlq_entry = DeadLetterEntry(
                    entry_id=dlq_id,
                    task_id=task_id,
                    scan_id=scan_id,
                    tenant_id=tenant_id,
                    task_type=task_type,
                    target=target,
                    worker_id=worker_id,
                    attempts=current_attempts,
                    last_error=error_message,
                )
                self._dead_letter_queue.append(dlq_entry)
                logger.error("Task %s moved to Dead Letter Queue (Attempts: %d): %s", task_id, current_attempts, error_message)
                return {
                    "action": "DEAD_LETTER",
                    "attempts": current_attempts,
                    "error_category": category.value,
                    "dlq_entry_id": dlq_id,
                }

            # Otherwise, schedule transient retry
            logger.info("Task %s eligible for transient retry (%d/%d)", task_id, current_attempts, self.max_task_attempts)
            return {
                "action": "RETRY",
                "attempts": current_attempts,
                "error_category": category.value,
                "backoff_seconds": 2 ** current_attempts,
            }

    def get_dlq_entries(self) -> List[Dict[str, Any]]:
        """Returns DLQ entries for administration review."""
        return [
            {
                "entry_id": e.entry_id,
                "task_id": e.task_id,
                "scan_id": e.scan_id,
                "tenant_id": e.tenant_id,
                "task_type": e.task_type,
                "target": e.target,
                "worker_id": e.worker_id,
                "attempts": e.attempts,
                "last_error": e.last_error,
                "timestamp": e.timestamp,
            }
            for e in self._dead_letter_queue
        ]

    async def reset(self) -> None:
        """Resets the fault recovery engine."""
        async with self._lock:
            self._heartbeats.clear()
            self._dead_letter_queue.clear()
            self._task_attempts.clear()


fault_recovery_engine = FaultRecoveryEngine()
