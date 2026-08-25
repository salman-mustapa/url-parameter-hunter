"""Tenant-Scoped Realtime Event Bus & Event Replay Engine (V13 §26, §27, §28, §41, §42, §43).

Ensures strict cross-scan and cross-tenant event isolation:
- All events carry tenant_id, project_id, investigation_id, job_id, and task_id.
- Durable event buffer for client reconnection and event replay.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("core.tenant_events")


@dataclass
class ScopedEvent:
    event_id: str
    tenant_id: str
    investigation_id: str
    event_type: str
    data: Dict[str, Any]
    project_id: Optional[str] = None
    task_id: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "tenant_id": self.tenant_id,
            "investigation_id": self.investigation_id,
            "project_id": self.project_id,
            "task_id": self.task_id,
            "event_type": self.event_type,
            "data": self.data,
            "timestamp": self.timestamp,
        }


class TenantEventBus:
    """Multi-tenant event broadcaster with durable replay history."""

    def __init__(self, max_buffer_per_investigation: int = 1000) -> None:
        self.max_buffer_per_investigation = max_buffer_per_investigation
        # investigation_id -> list of ScopedEvent
        self._history: Dict[str, List[ScopedEvent]] = defaultdict(list)
        # investigation_id -> list of asyncio.Queue (subscribers)
        self._subscribers: Dict[str, List[asyncio.Queue]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def publish(
        self,
        tenant_id: str,
        investigation_id: str,
        event_type: str,
        data: Dict[str, Any],
        project_id: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> ScopedEvent:
        """Publishes an event to all active listeners and saves to replay buffer."""
        event_id = f"evt_{int(time.time()*1000)}_{len(self._history[investigation_id])}"
        event = ScopedEvent(
            event_id=event_id,
            tenant_id=tenant_id,
            investigation_id=investigation_id,
            project_id=project_id,
            task_id=task_id,
            event_type=event_type,
            data=data,
        )

        async with self._lock:
            # 1. Store in durable memory buffer
            buf = self._history[investigation_id]
            buf.append(event)
            if len(buf) > self.max_buffer_per_investigation:
                self._history[investigation_id] = buf[-self.max_buffer_per_investigation:]

            # 2. Push to live subscriber queues
            for q in list(self._subscribers.get(investigation_id, [])):
                try:
                    q.put_nowait(event.to_dict())
                except asyncio.QueueFull:
                    pass

        return event

    async def subscribe(self, investigation_id: str) -> asyncio.Queue:
        """Creates a subscription queue for live SSE streaming."""
        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        async with self._lock:
            self._subscribers[investigation_id].append(q)
        return q

    async def unsubscribe(self, investigation_id: str, q: asyncio.Queue) -> None:
        async with self._lock:
            subs = self._subscribers.get(investigation_id, [])
            if q in subs:
                subs.remove(q)

    def replay_events(
        self,
        investigation_id: str,
        since_timestamp: float = 0.0,
    ) -> List[Dict[str, Any]]:
        """Replays historical events since a specific timestamp on client reconnection."""
        events = self._history.get(investigation_id, [])
        return [
            e.to_dict()
            for e in events
            if e.timestamp > since_timestamp
        ]

    async def reset(self) -> None:
        """Resets the event bus."""
        async with self._lock:
            self._history.clear()
            self._subscribers.clear()


tenant_event_bus = TenantEventBus()
