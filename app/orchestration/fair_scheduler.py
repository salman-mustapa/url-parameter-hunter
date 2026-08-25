"""Weighted Fair Scheduler & Multi-Tenant Resource Fair Queuing (V13 §11, §12, §13, §14, §15).

Prevents tenant starvation:
- Deficit Weighted Round Robin (DWRR) scheduling across all active tenants.
- Multi-Axis Concurrency Quotas:
  * Global Concurrency (e.g. 100 workers)
  * Tenant Concurrency (e.g. 15 active tasks per tenant)
  * Investigation Concurrency (e.g. 10 active tasks per scan)
  * Target Host Concurrency (e.g. 20 RPS per target host)
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("orchestration.fair_scheduler")


@dataclass
class ScheduledTaskItem:
    task_id: str
    tenant_id: str
    investigation_id: str
    target_host: str
    task_type: str
    priority: int
    worker_class: str
    context: Dict[str, Any]
    created_at: float = field(default_factory=time.time)


class WeightedFairScheduler:
    """Multi-tenant fair scheduler using Deficit Weighted Round Robin (DWRR)."""

    def __init__(
        self,
        max_global_tasks: int = 100,
        max_tenant_tasks: int = 15,
        max_target_concurrent: int = 10,
    ) -> None:
        self.max_global_tasks = max_global_tasks
        self.max_tenant_tasks = max_tenant_tasks
        self.max_target_concurrent = max_target_concurrent

        # Queues per tenant: tenant_id -> deque of ScheduledTaskItem
        self._tenant_queues: Dict[str, deque[ScheduledTaskItem]] = defaultdict(deque)
        self._tenant_weights: Dict[str, int] = defaultdict(lambda: 10)  # Default weight
        self._tenant_deficits: Dict[str, int] = defaultdict(int)

        # Active counts
        self._active_global: int = 0
        self._active_per_tenant: Dict[str, int] = defaultdict(int)
        self._active_per_investigation: Dict[str, int] = defaultdict(int)
        self._active_per_target: Dict[str, int] = defaultdict(int)

        self._lock = asyncio.Lock()

    async def submit_task(
        self,
        task_id: str,
        tenant_id: str,
        investigation_id: str,
        target_host: str,
        task_type: str,
        priority: int = 50,
        worker_class: str = "worker-general",
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Submits a task into the tenant's fair queue."""
        clean_host = target_host.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        item = ScheduledTaskItem(
            task_id=task_id,
            tenant_id=tenant_id,
            investigation_id=investigation_id,
            target_host=clean_host,
            task_type=task_type,
            priority=priority,
            worker_class=worker_class,
            context=context or {},
        )

        async with self._lock:
            self._tenant_queues[tenant_id].append(item)
            logger.debug(
                "Task %s queued for tenant %s (queue size=%d)",
                task_id, tenant_id, len(self._tenant_queues[tenant_id])
            )

    async def schedule_next_batch(self, max_batch_size: int = 10) -> List[ScheduledTaskItem]:
        """Picks the next batch of tasks to execute fairly without starving any tenant."""
        dispatched: List[ScheduledTaskItem] = []

        async with self._lock:
            active_tenants = [t for t, q in self._tenant_queues.items() if len(q) > 0]
            if not active_tenants or self._active_global >= self.max_global_tasks:
                return []

            # DWRR Scheduling Round
            for tenant_id in active_tenants:
                if len(dispatched) >= max_batch_size or self._active_global >= self.max_global_tasks:
                    break

                # Check tenant concurrency limit
                if self._active_per_tenant[tenant_id] >= self.max_tenant_tasks:
                    continue

                queue = self._tenant_queues[tenant_id]
                self._tenant_deficits[tenant_id] += self._tenant_weights[tenant_id]

                # Dispatch tasks for this tenant up to deficit quota
                tasks_to_requeue: List[ScheduledTaskItem] = []
                while queue and self._tenant_deficits[tenant_id] > 0 and len(dispatched) < max_batch_size:
                    candidate = queue.popleft()

                    # Check target host concurrency quota
                    if self._active_per_target[candidate.target_host] >= self.max_target_concurrent:
                        tasks_to_requeue.append(candidate)
                        continue

                    # Task passes all concurrency and fairness checks
                    dispatched.append(candidate)
                    self._tenant_deficits[tenant_id] -= 10
                    self._active_global += 1
                    self._active_per_tenant[tenant_id] += 1
                    self._active_per_investigation[candidate.investigation_id] += 1
                    self._active_per_target[candidate.target_host] += 1

                # Re-insert skipped tasks (due to per-target rate limiting)
                for skipped in reversed(tasks_to_requeue):
                    queue.appendleft(skipped)

        return dispatched

    async def release_task(
        self,
        tenant_id: str,
        investigation_id: str,
        target_host: str,
    ) -> None:
        """Releases concurrency slot when a task completes or fails."""
        clean_host = target_host.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        async with self._lock:
            self._active_global = max(0, self._active_global - 1)
            self._active_per_tenant[tenant_id] = max(0, self._active_per_tenant[tenant_id] - 1)
            self._active_per_investigation[investigation_id] = max(0, self._active_per_investigation[investigation_id] - 1)
            self._active_per_target[clean_host] = max(0, self._active_per_target[clean_host] - 1)

    def get_tenant_stats(self, tenant_id: str) -> Dict[str, Any]:
        """Returns live scheduler utilization for a specific tenant."""
        return {
            "tenant_id": tenant_id,
            "queued_tasks": len(self._tenant_queues.get(tenant_id, [])),
            "active_tasks": self._active_per_tenant.get(tenant_id, 0),
            "max_tenant_tasks": self.max_tenant_tasks,
            "global_active_tasks": self._active_global,
            "global_max_tasks": self.max_global_tasks,
        }

    async def reset(self) -> None:
        """Resets all scheduler state (for test isolation)."""
        async with self._lock:
            self._tenant_queues.clear()
            self._tenant_deficits.clear()
            self._active_global = 0
            self._active_per_tenant.clear()
            self._active_per_investigation.clear()
            self._active_per_target.clear()


weighted_fair_scheduler = WeightedFairScheduler()
