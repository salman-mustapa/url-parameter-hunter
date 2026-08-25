import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("event_bus")


class EventBus:
    """Pub/Sub event bus backed by Redis when available, with resilient in-memory fallback.
    Persists events to DB via persist hook and fans out to SSE subscribers.
    Implements Architecture v2 §9 & §41 event contract.
    """

    CHANNEL = "bughunter:events"

    def __init__(self, max_recent: int = 1000) -> None:
        self._subscribers: Dict[str, List[Any]] = {}
        self._recent: List[dict] = []
        self._max_recent = max_recent
        self._persist: Optional[Callable] = None
        self._redis: Optional[Any] = None
        self._pubsub_task: Optional[asyncio.Task] = None

    # ── Redis lifecycle ──────────────────────────────────────────────

    async def connect_redis(self, redis_url: str) -> None:
        """Connect to Redis for Pub/Sub. Falls back to in-memory on failure."""
        try:
            import redis.asyncio as aioredis
            self._redis = aioredis.from_url(redis_url, decode_responses=True)
            await self._redis.ping()
            logger.info("EventBus connected to Redis at %s", redis_url)
            # Start subscriber listener
            self._pubsub_task = asyncio.create_task(self._redis_listener())
        except Exception:
            logger.warning("Redis unavailable — EventBus using in-memory fallback")
            self._redis = None

    async def _redis_listener(self) -> None:
        """Listen for Redis Pub/Sub messages and fan out to local subscribers."""
        if not self._redis:
            return
        try:
            pubsub = self._redis.pubsub()
            await pubsub.subscribe(self.CHANNEL)
            async for message in pubsub.listen():
                if message["type"] == "message":
                    try:
                        event = json.loads(message["data"])
                        # Fan out to local subscribers without re-publishing to Redis
                        await self._local_fanout(event)
                    except Exception:
                        logger.exception("redis listener: failed to process message")
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception("redis listener crashed")

    async def close(self) -> None:
        """Shutdown Redis connection and listener."""
        if self._pubsub_task:
            self._pubsub_task.cancel()
            try:
                await self._pubsub_task
            except asyncio.CancelledError:
                pass
        if self._redis:
            await self._redis.aclose()
            self._redis = None

    # ── Pub/Sub ──────────────────────────────────────────────────────

    def set_persister(self, fn: Callable) -> None:
        self._persist = fn

    def subscribe(self, event_type: str, handler: Any) -> None:
        handlers = self._subscribers.setdefault(event_type, [])
        if handler not in handlers:
            handlers.append(handler)

    def unsubscribe(self, handler: Any) -> None:
        for handlers in self._subscribers.values():
            if handler in handlers:
                handlers.remove(handler)

    @staticmethod
    def make_event(
        scan_id: str,
        event_type: str,
        message: str,
        *,
        asset_id: Optional[str] = None,
        status: str = "INFO",
        data: Optional[dict] = None,
    ) -> dict:
        """Create a structured event conforming to §41 event contract."""
        evt = {
            "event_id": f"evt_{uuid.uuid4().hex[:12]}",
            "scan_id": scan_id,
            "type": event_type,
            "event_type": event_type,
            "status": status,
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if asset_id:
            evt["asset_id"] = asset_id
        if data:
            evt["data"] = data
        return evt

    async def publish(self, event: dict) -> None:
        """Publish event. If Redis is available, publish there; otherwise local fanout."""
        if not isinstance(event, dict):
            return

        # Ensure event_id and timestamps exist
        if "event_id" not in event:
            event["event_id"] = f"evt_{uuid.uuid4().hex[:12]}"
        now_iso = datetime.now(timezone.utc).isoformat()
        if "timestamp" not in event:
            event["timestamp"] = now_iso
        if "created_at" not in event:
            event["created_at"] = event.get("timestamp") or now_iso
        if "type" not in event and "event_type" in event:
            event["type"] = event["event_type"]
        elif "event_type" not in event and "type" in event:
            event["event_type"] = event["type"]

        # Store in recent buffer
        self._recent.append(event)
        if len(self._recent) > self._max_recent:
            self._recent = self._recent[-self._max_recent:]

        # Persist to DB
        if self._persist:
            try:
                await self._persist(event)
            except Exception:
                logger.exception("event persist failed")

        # Publish to Redis or local fanout
        if self._redis:
            try:
                serialized = json.dumps(event, default=str)
                await self._redis.publish(self.CHANNEL, serialized)
            except Exception as exc:
                logger.warning("Redis publish failed (%s), falling back to local fanout", exc)
                await self._local_fanout(event)
        else:
            await self._local_fanout(event)

    async def _local_fanout(self, event: dict) -> None:
        """Fan out event to specific subscribers matching event type, plus wildcard subscribers."""
        evt_type = event.get("type") or event.get("event_type") or "*"
        handlers: List[Any] = []
        if evt_type in self._subscribers:
            handlers.extend(self._subscribers[evt_type])
        if "*" in self._subscribers and evt_type != "*":
            handlers.extend(self._subscribers["*"])

        # Deduplicate while preserving invocation order
        seen = set()
        unique_handlers = []
        for h in handlers:
            if h not in seen:
                seen.add(h)
                unique_handlers.append(h)

        for handler in unique_handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(event)
                else:
                    handler(event)
            except Exception:
                logger.exception("event subscriber failed for event_type '%s'", evt_type)

    def get_recent(self, scan_id: Optional[str] = None, limit: int = 200) -> List[dict]:
        out = self._recent
        if scan_id:
            out = [e for e in out if e.get("scan_id") == scan_id]
        return out[-limit:]

    def serialize(self, event: dict) -> str:
        return json.dumps(event, default=str)


event_bus = EventBus()