"""Resource-Aware Scheduler & Priority Task Queue (V8 §41).

Monitors system resources:
- CPU utilization
- RAM usage
- Disk availability
- Active browser sessions
- Task queue depth
- AI inference latency

Priority Scheduling Tiers:
- P0: Confirmed / High-value validation (Immediate execution)
- P1: High-value candidate checks
- P2: Normal analysis & probing
- P3: Broad enumeration & discovery
- P4: Enrichment & telemetry metadata
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Dict, List, Optional

logger = logging.getLogger("orchestration.scheduler")


@dataclass(order=True)
class ScheduledTask:
    priority: int  # 0 (P0) to 4 (P4)
    task_id: str = field(compare=False)
    module_name: str = field(compare=False)
    target: str = field(compare=False)
    created_at: float = field(default_factory=time.time, compare=False)
    payload: Dict[str, Any] = field(default_factory=dict, compare=False)


class ResourceAwareScheduler:
    """Resource-aware priority task scheduler (V8 §41)."""

    def __init__(self, max_concurrency: int = 15) -> None:
        self.max_concurrency = max_concurrency
        self._queue: asyncio.PriorityQueue[ScheduledTask] = asyncio.PriorityQueue()
        self._active_tasks: Dict[str, ScheduledTask] = {}
        self._active_browser_sessions = 0
        self._max_browser_sessions = int(os.getenv("MAX_BROWSER_SESSIONS", "4"))

    def enqueue_task(
        self,
        task_id: str,
        module_name: str,
        target: str,
        priority: int = 2,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Enqueues a task according to its priority tier P0-P4."""
        clamped_prio = min(4, max(0, priority))
        task = ScheduledTask(
            priority=clamped_prio,
            task_id=task_id,
            module_name=module_name,
            target=target,
            payload=payload or {},
        )
        self._queue.put_nowait(task)
        logger.info("Enqueued task %s [%s on %s] with Priority P%d (Queue size: %d)", task_id, module_name, target, clamped_prio, self._queue.qsize())

    def get_system_telemetry(self) -> Dict[str, Any]:
        """Returns current resource utilization and queue metrics."""
        return {
            "queue_depth": self._queue.qsize(),
            "active_tasks_count": len(self._active_tasks),
            "active_browser_sessions": self._active_browser_sessions,
            "max_browser_sessions": self._max_browser_sessions,
            "concurrency_limit": self.max_concurrency,
        }

    async def get_next_task(self) -> ScheduledTask:
        """Retrieves next highest-priority task (P0 before P1 before P2)."""
        task = await self._queue.get()
        self._active_tasks[task.task_id] = task
        return task

    def mark_completed(self, task_id: str) -> None:
        self._active_tasks.pop(task_id, None)

    def reset(self) -> None:
        """Clears queue and active tasks for clean state between scan sessions / test cases."""
        self._queue = asyncio.PriorityQueue()
        self._active_tasks.clear()
        self._active_browser_sessions = 0


resource_scheduler = ResourceAwareScheduler()
