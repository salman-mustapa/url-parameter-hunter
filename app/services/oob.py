import asyncio
import json
import uuid
import logging
from typing import Optional, Tuple
import redis.asyncio as aioredis

from app.core.config import settings

logger = logging.getLogger("services.oob")


class OOBService:
    def __init__(self, redis_url: str = settings.redis_url):
        self.redis_url = redis_url
        self._redis: Optional[aioredis.Redis] = None
        self._fallback_db = {}  # In-memory fallback if Redis is down

    def _get_redis(self) -> aioredis.Redis:
        if self._redis is None:
            self._redis = aioredis.from_url(self.redis_url, decode_responses=True)
        return self._redis

    def generate_interaction_url(self) -> Tuple[str, str]:
        correlation_id = uuid.uuid4().hex[:12]
        host = settings.oob_callback_host or "localhost:9001"
        if not host.startswith(("http://", "https://")):
            host = f"http://{host}"
        callback_url = f"{host.rstrip('/')}/api/oob/{correlation_id}"
        return correlation_id, callback_url

    async def log_interaction(self, correlation_id: str, metadata: dict) -> None:
        """Stores the interaction in Redis or fallback in-memory DB."""
        try:
            r = self._get_redis()
            # Set key to expire in 1 hour
            await r.setex(f"oob:{correlation_id}", 3600, json.dumps(metadata))
            await r.publish("bughunter:oob:interactions", json.dumps({"correlation_id": correlation_id, **metadata}))
            logger.info("OOB interaction logged for %s", correlation_id)
        except Exception as e:
            logger.warning("Redis logging failed for OOB %s, using fallback: %s", correlation_id, e)
            self._fallback_db[correlation_id] = metadata

    async def check_interaction(self, correlation_id: str, timeout: float = 5.0) -> Optional[dict]:
        """Check if an interaction occurred for the given correlation_id, up to timeout."""
        start_time = asyncio.get_event_loop().time()
        while True:
            # Check fallback first
            if correlation_id in self._fallback_db:
                return self._fallback_db.get(correlation_id)

            try:
                r = self._get_redis()
                val = await r.get(f"oob:{correlation_id}")
                if val:
                    return json.loads(val)
            except Exception as e:
                logger.debug("Redis error checking OOB %s: %s", correlation_id, e)

            if asyncio.get_event_loop().time() - start_time >= timeout:
                break
            await asyncio.sleep(0.5)

        return None

    async def close(self) -> None:
        if self._redis:
            try:
                await self._redis.aclose()
            except Exception:
                pass
            self._redis = None


oob_service = OOBService()
