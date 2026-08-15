import json
import logging
from datetime import datetime, timezone
from typing import Awaitable, Callable, Dict, List
import redis.asyncio as redis
from app.core.config import settings

logger = logging.getLogger("event_bus")

class EventBus:
    def __init__(self):
        self.redis: redis.Redis | None = None
        self._subscribers: Dict[str, List[Callable[[dict], Awaitable[None]]]] = {}

    async def init(self):
        self.redis = redis.from_url(settings.redis_url, decode_responses=True)
        try:
            await self.redis.ping()
            logger.info("Connected to Redis")
        except Exception as exc:
            logger.warning("Redis unavailable: %s", exc)
            self.redis = None

    async def close(self):
        if self.redis:
            await self.redis.aclose()

    def subscribe(self, event_type: str, handler: Callable[[dict], Awaitable[None]]):
        self._subscribers.setdefault(event_type, []).append(handler)

    async def publish(self, event: dict):
        event.setdefault("created_at", datetime.now(timezone.utc).isoformat())
        channel = event.get("event_type", "unknown")
        logger.info("PUBLISH %s", channel)
        if self.redis:
            try:
                await self.redis.publish("scan_events", json.dumps(event))
            except Exception as exc:
                logger.warning("Publish failed: %s", exc)
        for handler in self._subscribers.get(channel, []):
            try:
                await handler(event)
            except Exception as exc:
                logger.exception("Event handler failed for %s: %s", channel, exc)

event_bus = EventBus()
