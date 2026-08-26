"""Distributed Queue & Redis Streams Consumer Group Topology (V13 §9, §10, §45).

Manages distributed task dispatch across consumer groups:
- Streams: scan.discovery, scan.network, scan.web, scan.crawler, scan.artifact,
           scan.intelligence, scan.validation, scan.browser, scan.ai, scan.evidence, scan.reporting
- Worker Acknowledgement (XACK), Pending Entries List (XPENDING), and Stale Task Claiming (XCLAIM).
- 100% Transparent In-Memory Fallback when Redis is not running or in standalone test mode.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("orchestration.distributed_queue")


@dataclass
class QueueMessage:
    message_id: str
    stream: str
    payload: Dict[str, Any]
    idempotency_key: str
    priority: int = 50
    created_at: float = field(default_factory=time.time)
    delivered_at: Optional[float] = None
    delivery_count: int = 0
    consumer_id: Optional[str] = None
    acked: bool = False


class DistributedTaskQueue:
    """Enterprise distributed queue supporting Redis Streams and robust In-Memory fallback."""

    STREAM_NAMES = [
        "scan.discovery",
        "scan.network",
        "scan.web",
        "scan.crawler",
        "scan.artifact",
        "scan.intelligence",
        "scan.validation",
        "scan.browser",
        "scan.ai",
        "scan.evidence",
        "scan.reporting",
    ]

    def __init__(self, redis_url: Optional[str] = None) -> None:
        self.redis_url = redis_url or os.getenv("REDIS_URL", "")
        self.use_redis = bool(self.redis_url)
        self._redis_client = None
        
        # In-memory storage structures for standalone / test mode
        self._streams: Dict[str, List[QueueMessage]] = {s: [] for s in self.STREAM_NAMES}
        self._pending: Dict[str, Dict[str, QueueMessage]] = {}  # stream -> {msg_id: msg}
        self._seen_idempotency_keys: Set[str] = set()
        self._lock = asyncio.Lock()

    def _get_redis(self):
        if self.use_redis and self._redis_client is None:
            import redis.asyncio as aioredis
            self._redis_client = aioredis.from_url(self.redis_url, decode_responses=True)
        return self._redis_client

    async def _ensure_group(self, r, stream_name: str, group_name: str) -> None:
        try:
            # Create stream and group if they don't exist
            # MKSTREAM will auto-create the stream
            await r.xgroup_create(stream_name, group_name, id="0", mkstream=True)
        except Exception as e:
            # Group already exists
            if "BUSYGROUP" not in str(e):
                logger.debug("XGROUP CREATE warning: %s", e)

    async def enqueue(
        self,
        stream_name: str,
        payload: Dict[str, Any],
        idempotency_key: str,
        priority: int = 50,
    ) -> Optional[str]:
        """Pushes a task into the distributed stream with idempotency deduplication."""
        if stream_name not in self.STREAM_NAMES:
            stream_name = "scan.validation"

        r = self._get_redis()
        if r:
            try:
                # Idempotency deduplication via Redis SETNX with 24 hours expiry
                dedup_key = f"bughunter:queue:idempotency:{idempotency_key}"
                is_new = await r.set(dedup_key, "1", ex=86400, nx=True)
                if not is_new:
                    logger.debug("Duplicate task ignored by Redis idempotency_key: %s", idempotency_key)
                    return None

                # Push to Redis Stream
                fields = {
                    "payload": json.dumps(payload),
                    "idempotency_key": idempotency_key,
                    "priority": str(priority),
                    "created_at": str(time.time()),
                }
                msg_id = await r.xadd(stream_name, fields)
                logger.debug("Enqueued message %s into Redis stream %s (priority=%d)", msg_id, stream_name, priority)
                return msg_id
            except Exception as e:
                logger.warning("Redis enqueue failed, falling back to in-memory: %s", e)

        async with self._lock:
            # Idempotency deduplication check
            if idempotency_key in self._seen_idempotency_keys:
                logger.debug("Duplicate task ignored by idempotency_key: %s", idempotency_key)
                return None
            self._seen_idempotency_keys.add(idempotency_key)

            msg_id = f"{int(time.time()*1000)}-{len(self._streams[stream_name])}"
            msg = QueueMessage(
                message_id=msg_id,
                stream=stream_name,
                payload=payload,
                idempotency_key=idempotency_key,
                priority=priority,
            )

            # Keep queue ordered by priority descending (higher priority first)
            self._streams[stream_name].append(msg)
            self._streams[stream_name].sort(key=lambda m: m.priority, reverse=True)
            logger.debug("Enqueued message %s into %s (priority=%d)", msg_id, stream_name, priority)
            return msg_id

    async def claim_tasks(
        self,
        stream_name: str,
        group_name: str,
        consumer_name: str,
        count: int = 1,
    ) -> List[Dict[str, Any]]:
        """Claims unassigned messages from the stream for a worker consumer."""
        if stream_name not in self.STREAM_NAMES:
            return []

        r = self._get_redis()
        if r:
            try:
                await self._ensure_group(r, stream_name, group_name)
                messages = await r.xreadgroup(
                    groupname=group_name,
                    consumername=consumer_name,
                    streams={stream_name: ">"},
                    count=count,
                )
                
                claimed: List[Dict[str, Any]] = []
                if messages:
                    for stream, msgs in messages:
                        for msg_id, fields in msgs:
                            payload = json.loads(fields.get("payload", "{}"))
                            priority = int(fields.get("priority", "50"))
                            idempotency_key = fields.get("idempotency_key", "")
                            
                            claimed.append({
                                "message_id": msg_id,
                                "stream": stream_name,
                                "idempotency_key": idempotency_key,
                                "priority": priority,
                                "payload": payload,
                                "delivery_count": 1,
                            })
                return claimed
            except Exception as e:
                logger.warning("Redis claim_tasks failed, falling back to in-memory: %s", e)

        claimed: List[Dict[str, Any]] = []
        async with self._lock:
            available = [m for m in self._streams[stream_name] if not m.acked and m.consumer_id is None]
            for msg in available[:count]:
                msg.consumer_id = consumer_name
                msg.delivered_at = time.time()
                msg.delivery_count += 1
                
                # Add to pending list
                if stream_name not in self._pending:
                    self._pending[stream_name] = {}
                self._pending[stream_name][msg.message_id] = msg

                claimed.append({
                    "message_id": msg.message_id,
                    "stream": stream_name,
                    "idempotency_key": msg.idempotency_key,
                    "priority": msg.priority,
                    "payload": msg.payload,
                    "delivery_count": msg.delivery_count,
                })
        return claimed

    async def ack(self, stream_name: str, group_name: str, message_id: str) -> bool:
        """Acknowledges successful processing of a message (XACK)."""
        r = self._get_redis()
        if r:
            try:
                await r.xack(stream_name, group_name, message_id)
                await r.xdel(stream_name, message_id)
                return True
            except Exception as e:
                logger.warning("Redis ACK failed: %s", e)

        async with self._lock:
            # Remove from stream and pending
            if stream_name in self._pending and message_id in self._pending[stream_name]:
                del self._pending[stream_name][message_id]

            if stream_name in self._streams:
                self._streams[stream_name] = [
                    m for m in self._streams[stream_name] if m.message_id != message_id
                ]
            return True

    async def claim_stale_tasks(
        self,
        stream_name: str,
        group_name: str,
        consumer_name: str,
        min_idle_ms: int = 30000,
    ) -> List[Dict[str, Any]]:
        """Recovers orphaned tasks where worker heartbeat expired (XCLAIM)."""
        r = self._get_redis()
        if r:
            try:
                await self._ensure_group(r, stream_name, group_name)
                pending_info = await r.xpending_range(
                    name=stream_name,
                    groupname=group_name,
                    min="-",
                    max="+",
                    count=50,
                )
                
                recovered: List[Dict[str, Any]] = []
                if pending_info:
                    msg_ids_to_claim = []
                    for item in pending_info:
                        msg_id = item["message_id"]
                        idle_time_ms = item["elapsed_milliseconds"]
                        if idle_time_ms >= min_idle_ms:
                            msg_ids_to_claim.append(msg_id)
                            
                    if msg_ids_to_claim:
                        claimed_msgs = await r.xclaim(
                            name=stream_name,
                            groupname=group_name,
                            consumername=consumer_name,
                            min_idle_time=min_idle_ms,
                            keys=msg_ids_to_claim,
                        )
                        for msg_id, fields in claimed_msgs:
                            payload = json.loads(fields.get("payload", "{}"))
                            priority = int(fields.get("priority", "50"))
                            idempotency_key = fields.get("idempotency_key", "")
                            
                            recovered.append({
                                "message_id": msg_id,
                                "stream": stream_name,
                                "idempotency_key": idempotency_key,
                                "priority": priority,
                                "payload": payload,
                                "delivery_count": 2,
                                "is_recovered": True,
                            })
                return recovered
            except Exception as e:
                logger.warning("Redis claim_stale_tasks failed: %s", e)

        recovered: List[Dict[str, Any]] = []
        now = time.time()
        min_idle_sec = min_idle_ms / 1000.0

        async with self._lock:
            pending_map = self._pending.get(stream_name, {})
            for msg in list(pending_map.values()):
                idle_time = now - (msg.delivered_at or 0)
                if idle_time >= min_idle_sec:
                    logger.warning(
                        "Reclaiming stale task %s from inactive worker %s to %s",
                        msg.message_id, msg.consumer_id, consumer_name
                    )
                    msg.consumer_id = consumer_name
                    msg.delivered_at = now
                    msg.delivery_count += 1
                    recovered.append({
                        "message_id": msg.message_id,
                        "stream": stream_name,
                        "idempotency_key": msg.idempotency_key,
                        "priority": msg.priority,
                        "payload": msg.payload,
                        "delivery_count": msg.delivery_count,
                        "is_recovered": True,
                    })
        return recovered

    async def get_queue_depths(self) -> Dict[str, int]:
        """Returns depth of all queues for monitoring."""
        r = self._get_redis()
        if r:
            try:
                depths = {}
                for s in self.STREAM_NAMES:
                    try:
                        len_val = await r.xlen(s)
                        depths[s] = len_val
                    except Exception:
                        depths[s] = 0
                return depths
            except Exception:
                pass

        async with self._lock:
            return {
                s: len([m for m in msgs if not m.acked and m.consumer_id is None])
                for s, msgs in self._streams.items()
            }

    async def reset(self) -> None:
        """Resets all stream queues (for unit test isolation)."""
        r = self._get_redis()
        if r:
            try:
                for s in self.STREAM_NAMES:
                    await r.delete(s)
                keys = await r.keys("bughunter:queue:idempotency:*")
                if keys:
                    await r.delete(*keys)
            except Exception as e:
                logger.debug("Redis reset warning: %s", e)

        async with self._lock:
            for s in self._streams:
                self._streams[s].clear()
            self._pending.clear()
            self._seen_idempotency_keys.clear()


distributed_queue = DistributedTaskQueue()
