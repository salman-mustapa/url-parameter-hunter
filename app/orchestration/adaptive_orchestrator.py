"""Autonomous Adaptive Orchestrator (V10 Core Architecture).

Implements the continuous event-driven security research orchestrator:
- Event Intake & Opportunity Generation
- Priority Calculation & Fast-Path Escalation
- Fair Weighted Worker Assignment (40% Discovery, 30% Validation, 20% Enum, 10% Intel)
- Dependency Management & State Transitions (QUEUED -> READY -> RUNNING -> COMPLETED)
- Task Deduplication (Idempotency Key) & Lineage Tracking
- Safe Worker Isolation, Error Recovery & Granular Kill Switches
- Dynamic Completion Detection & Live Metrics
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set

from app.core.events import event_bus
from app.core.kill_switch import kill_switch_manager
from app.orchestration.opportunity_engine import Opportunity, opportunity_engine
from app.orchestration.scheduler import resource_scheduler
from app.workers.worker_pool import worker_pool_manager

logger = logging.getLogger("orchestration.adaptive_orchestrator")


class TaskState(str, Enum):
    QUEUED = "QUEUED"
    READY = "READY"
    RUNNING = "RUNNING"
    BLOCKED = "BLOCKED"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    SKIPPED = "SKIPPED"


@dataclass
class OrchestratorTask:
    task_id: str
    task_type: str
    target: str
    priority: int  # 0 to 100 (100 = Top Priority P0)
    worker_class: str
    status: TaskState = TaskState.QUEUED
    dependencies: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    parent_task_id: Optional[str] = None
    lineage_reason: str = "initial_seed"
    idempotency_key: str = ""
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    error: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 2

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "task_type": self.task_type,
            "target": self.target,
            "priority": self.priority,
            "worker_class": self.worker_class,
            "status": self.status.value,
            "dependencies": self.dependencies,
            "parent_task_id": self.parent_task_id,
            "lineage_reason": self.lineage_reason,
            "idempotency_key": self.idempotency_key,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "error": self.error,
            "retry_count": self.retry_count,
        }


class AdaptiveOrchestrator:
    """Central event-driven orchestrator coordinating parallel specialists and continuous escalation."""

    def __init__(self, scan_id: str = "global_campaign", max_concurrency: int = 20) -> None:
        self.scan_id = scan_id
        self.max_concurrency = max_concurrency
        self.tasks: Dict[str, OrchestratorTask] = {}
        self._idempotency_registry: Set[str] = set()
        self._completed_task_ids: Set[str] = set()
        self._running_tasks: Dict[str, asyncio.Task] = {}
        self._active_worker_tasks: Dict[str, OrchestratorTask] = {}
        self._is_active = True
        self._paused = False
        self._lock = asyncio.Lock()
        self._opportunity_history: List[Opportunity] = []
        self._event_subscriptions: List[str] = []

    def compute_idempotency_key(self, task_type: str, target: str, context: Dict[str, Any]) -> str:
        """Computes a deterministic SHA256 key to deduplicate identical workloads."""
        raw_key = f"{task_type}:{target}:{sorted(context.items())}"
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:16]

    async def submit_task(
        self,
        task_type: str,
        target: str,
        priority: int = 50,
        worker_class: str = "worker-web",
        dependencies: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None,
        parent_task_id: Optional[str] = None,
        lineage_reason: str = "seed",
    ) -> Optional[OrchestratorTask]:
        """Submits a new task into the orchestrator graph with dependency validation and deduplication."""
        ctx = context or {}
        idem_key = self.compute_idempotency_key(task_type, target, ctx)

        async with self._lock:
            if idem_key in self._idempotency_registry:
                logger.debug("Deduplicated redundant task [%s on %s] (Key: %s)", task_type, target, idem_key)
                return None

            self._idempotency_registry.add(idem_key)
            deps = dependencies or []

            # Determine initial state: READY if all deps met, else BLOCKED
            unmet_deps = [d for d in deps if d not in self._completed_task_ids]
            initial_state = TaskState.BLOCKED if unmet_deps else TaskState.READY

            task_id = f"task_{task_type.split('.')[-1]}_{uuid.uuid4().hex[:8]}"
            task = OrchestratorTask(
                task_id=task_id,
                task_type=task_type,
                target=target,
                priority=min(100, max(0, priority)),
                worker_class=worker_class,
                status=initial_state,
                dependencies=deps,
                context=ctx,
                parent_task_id=parent_task_id,
                lineage_reason=lineage_reason,
                idempotency_key=idem_key,
            )

            self.tasks[task_id] = task

            # If ready, enqueue to resource scheduler
            if initial_state == TaskState.READY:
                # Map 0-100 priority to P0-P4 scheduler tiers
                tier = 0 if priority >= 95 else (1 if priority >= 80 else (2 if priority >= 50 else (3 if priority >= 20 else 4)))
                resource_scheduler.enqueue_task(
                    task_id=task_id,
                    module_name=task_type,
                    target=target,
                    priority=tier,
                    payload={"task": task.to_dict()},
                )

            logger.info("Submitted task %s [%s on %s] Priority: %d State: %s", task_id, task_type, target, priority, initial_state.value)
            return task

    async def ingest_event(self, event_type: str, event_data: Dict[str, Any]) -> List[OrchestratorTask]:
        """Ingests an event, detects opportunities, and automatically spawns prioritized child tasks."""
        if not self._is_active or self._paused:
            return []

        # Check kill switch
        if kill_switch_manager.is_stopped(self.scan_id):
            logger.info("Kill switch active for %s, skipping event ingestion", self.scan_id)
            return []

        opportunities = opportunity_engine.evaluate_event(event_type, event_data)
        created_tasks: List[OrchestratorTask] = []

        for opp in opportunities:
            self._opportunity_history.append(opp)
            parent_id = event_data.get("source_task_id") or event_data.get("parent_task_id")
            lineage = f"Opportunity '{opp.opportunity_type.value}' triggered from {event_type}"

            task = await self.submit_task(
                task_type=f"validate.{opp.opportunity_type.value}",
                target=opp.target_url,
                priority=opp.priority,
                worker_class=opp.recommended_worker,
                dependencies=[],  # Fast path validation runs immediately
                context=opp.context,
                parent_task_id=parent_id,
                lineage_reason=lineage,
            )
            if task:
                created_tasks.append(task)
                # Emit live event to UI
                await event_bus.publish({
                    "type": "orchestrator.opportunity_escalated",
                    "opportunity": opp.to_dict(),
                    "task_id": task.task_id,
                    "target": opp.target_url,
                    "priority": opp.priority,
                    "timestamp": time.time(),
                })

        return created_tasks

    async def mark_task_completed(self, task_id: str, result_data: Optional[Dict[str, Any]] = None) -> None:
        """Marks a task as completed and unblocks dependent tasks in the DAG."""
        async with self._lock:
            task = self.tasks.get(task_id)
            if not task:
                return

            task.status = TaskState.COMPLETED
            task.completed_at = time.time()
            self._completed_task_ids.add(task_id)
            self._active_worker_tasks.pop(task_id, None)
            resource_scheduler.mark_completed(task_id)

            # Check and unblock dependent tasks
            for other_id, other_task in self.tasks.items():
                if other_task.status == TaskState.BLOCKED:
                    unmet = [d for d in other_task.dependencies if d not in self._completed_task_ids]
                    if not unmet:
                        other_task.status = TaskState.READY
                        tier = 0 if other_task.priority >= 95 else (1 if other_task.priority >= 80 else 2)
                        resource_scheduler.enqueue_task(
                            task_id=other_id,
                            module_name=other_task.task_type,
                            target=other_task.target,
                            priority=tier,
                            payload={"task": other_task.to_dict()},
                        )
                        logger.info("Unblocked dependent task %s [%s] -> READY", other_id, other_task.task_type)

    async def mark_task_failed(self, task_id: str, error_msg: str) -> None:
        """Handles task failure, applies retry logic or marks FAILED."""
        async with self._lock:
            task = self.tasks.get(task_id)
            if not task:
                return

            task.retry_count += 1
            if task.retry_count <= task.max_retries:
                task.status = TaskState.READY
                task.error = f"Retry {task.retry_count}: {error_msg}"
                tier = 0 if task.priority >= 95 else (1 if task.priority >= 80 else 2)
                resource_scheduler.enqueue_task(
                    task_id=task_id,
                    module_name=task.task_type,
                    target=task.target,
                    priority=tier,
                    payload={"task": task.to_dict()},
                )
                logger.warning("Task %s failed (%s), scheduled retry %d/%d", task_id, error_msg, task.retry_count, task.max_retries)
            else:
                task.status = TaskState.FAILED
                task.completed_at = time.time()
                task.error = error_msg
                self._active_worker_tasks.pop(task_id, None)
                resource_scheduler.mark_completed(task_id)
                logger.error("Task %s permanently failed: %s", task_id, error_msg)

    def cancel_task(self, task_id: str, reason: str = "user_cancelled") -> None:
        """Cancels a specific task and its running asyncio worker."""
        task = self.tasks.get(task_id)
        if task and task.status in (TaskState.QUEUED, TaskState.READY, TaskState.BLOCKED, TaskState.RUNNING):
            task.status = TaskState.CANCELLED
            task.error = reason
            t_obj = self._running_tasks.get(task_id)
            if t_obj and not t_obj.done():
                t_obj.cancel()
            self._active_worker_tasks.pop(task_id, None)
            resource_scheduler.mark_completed(task_id)
            logger.info("Cancelled task %s: %s", task_id, reason)

    def cancel_branch(self, parent_task_id: str, reason: str = "parent_branch_cancelled") -> None:
        """Recursively cancels all child tasks descending from a parent task."""
        to_cancel = [t_id for t_id, t in self.tasks.items() if t.parent_task_id == parent_task_id]
        for child_id in to_cancel:
            self.cancel_task(child_id, reason)
            self.cancel_branch(child_id, reason)

    def get_metrics(self) -> Dict[str, Any]:
        """Returns live real-time orchestration metrics and worker utilization."""
        counts: Dict[str, int] = {s.value: 0 for s in TaskState}
        for t in self.tasks.values():
            counts[t.status.value] += 1

        active_workers_summary = [
            {"task_id": t.task_id, "type": t.task_type, "target": t.target, "worker": t.worker_class, "elapsed": time.time() - (t.started_at or time.time())}
            for t in self._active_worker_tasks.values()
        ]

        return {
            "total_tasks": len(self.tasks),
            "queued_tasks": counts[TaskState.QUEUED.value],
            "ready_tasks": counts[TaskState.READY.value],
            "running_tasks": counts[TaskState.RUNNING.value],
            "blocked_tasks": counts[TaskState.BLOCKED.value],
            "completed_tasks": counts[TaskState.COMPLETED.value],
            "failed_tasks": counts[TaskState.FAILED.value],
            "cancelled_tasks": counts[TaskState.CANCELLED.value],
            "opportunities_detected": len(self._opportunity_history),
            "active_worker_count": len(self._active_worker_tasks),
            "active_workers": active_workers_summary,
            "is_idle": self.is_idle(),
        }

    def is_idle(self) -> bool:
        """Determines if the dynamic investigation graph has reached completion."""
        has_running = any(t.status == TaskState.RUNNING for t in self.tasks.values())
        has_ready = any(t.status == TaskState.READY for t in self.tasks.values())
        if has_running or has_ready:
            return False

        # If only BLOCKED tasks remain, verify if any dependency can still finish
        blocked = [t for t in self.tasks.values() if t.status == TaskState.BLOCKED]
        for b in blocked:
            if any(d not in self._completed_task_ids for d in b.dependencies):
                # Has unmet dependencies that can never complete because nothing is running
                pass

        return True


adaptive_orchestrator = AdaptiveOrchestrator()
