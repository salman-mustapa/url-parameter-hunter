import asyncio
import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("event_bus")


class EventBus:
    """In-process pub/sub. Persists events to DB via persist hook + fans out to SSE subscribers."""

    def __init__(self, max_recent: int = 1000) -> None:
        self._subscribers: Dict[str, List[Any]] = {}
        self._recent: List[dict] = []
        self._max_recent = max_recent
        self._persist: Optional[Any] = None

    def set_persister(self, fn: Any) -> None:
        self._persist = fn

    def subscribe(self, event_type: str, handler: Any) -> None:
        self._subscribers.setdefault(event_type, []).append(handler)
        if event_type != "*":
            self._subscribers.setdefault("*", []).append(handler)

    def unsubscribe(self, handler: Any) -> None:
        for handlers in self._subscribers.values():
            if handler in handlers:
                handlers.remove(handler)

    async def publish(self, event: dict) -> None:
        self._recent.append(event)
        if len(self._recent) > self._max_recent:
            self._recent = self._recent[-self._max_recent:]
        if self._persist:
            try:
                await self._persist(event)
            except Exception:
                logger.exception("event persist failed")
        for handler in list(self._subscribers.get("*", [])):
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(event)
                else:
                    handler(event)
            except Exception:
                logger.exception("event subscriber failed")

    def get_recent(self, scan_id: Optional[str] = None, limit: int = 200) -> List[dict]:
        out = self._recent
        if scan_id:
            out = [e for e in out if e.get("scan_id") == scan_id]
        return out[-limit:]

    def serialize(self, event: dict) -> str:
        return json.dumps(event, default=str)


event_bus = EventBus()