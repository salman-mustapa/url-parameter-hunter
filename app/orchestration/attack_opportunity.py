"""Universal Attack Opportunity & Opportunity Bus (Autonomous Engine V15).

Implements the high-throughput, event-driven opportunity backbone:
- Continuous discovery-to-attack routing with priority queues (0-100 score).
- State lifecycle tracking: DISCOVERED -> QUEUED -> TESTING -> SUSPECTED -> VALIDATING -> CONFIRMED -> EXPLOITED -> BLOCKED / INCONCLUSIVE / REJECTED.
- Host-level concurrency management & rate limiting.
- Deduplication via deterministic opportunity fingerprinting.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("orchestration.attack_opportunity")


class OpportunityState(str, Enum):
    DISCOVERED = "DISCOVERED"
    QUEUED = "QUEUED"
    TESTING = "TESTING"
    SUSPECTED = "SUSPECTED"
    VALIDATING = "VALIDATING"
    CONFIRMED = "CONFIRMED"
    EXPLOITED = "EXPLOITED"
    BLOCKED = "BLOCKED"
    INCONCLUSIVE = "INCONCLUSIVE"
    REJECTED = "REJECTED"


@dataclass
class AttackOpportunity:
    id: str = field(default_factory=lambda: f"opp_{uuid.uuid4().hex[:10]}")
    target: str = ""
    asset_id: Optional[str] = None
    endpoint: str = ""
    protocol: str = "http"  # http, https, tcp, udp, etc.
    service: str = "http"   # http, https, mysql, redis, mongodb, ftp, etc.
    technology: Optional[str] = None
    parameter: Optional[str] = None
    artifact: Optional[str] = None
    hypothesis: str = ""
    attack_type: str = "general"  # sqli, xss, auth, idor, ssrf, traversal, rce, service, artifact
    prerequisites: List[str] = field(default_factory=list)
    confidence: float = 0.5  # 0.0 to 1.0
    priority: int = 50       # 0 to 100 (100 = Immediate Fast Path P0)
    evidence: Dict[str, Any] = field(default_factory=dict)
    state: OpportunityState = OpportunityState.DISCOVERED
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def fingerprint(self) -> str:
        """Generates deterministic fingerprint for deduplication."""
        raw = f"{self.metadata.get('scan_id', '')}|{self.target}|{self.endpoint}|{self.parameter or ''}|{self.attack_type}|{self.artifact or ''}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    @property
    def host(self) -> str:
        """Extracts the host from target or endpoint."""
        if "://" in self.target:
            return urlparse(self.target).netloc.split(":")[0]
        if "://" in self.endpoint:
            return urlparse(self.endpoint).netloc.split(":")[0]
        return self.target.split(":")[0] if self.target else "localhost"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "asset_id": self.asset_id,
            "endpoint": self.endpoint,
            "protocol": self.protocol,
            "service": self.service,
            "technology": self.technology,
            "parameter": self.parameter,
            "artifact": self.artifact,
            "hypothesis": self.hypothesis,
            "attack_type": self.attack_type,
            "prerequisites": self.prerequisites,
            "confidence": self.confidence,
            "priority": self.priority,
            "evidence": self.evidence,
            "state": self.state.value if isinstance(self.state, OpportunityState) else str(self.state),
            "metadata": self.metadata,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "fingerprint": self.fingerprint(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AttackOpportunity:
        state_val = data.get("state", OpportunityState.DISCOVERED)
        if isinstance(state_val, str):
            try:
                state = OpportunityState(state_val)
            except ValueError:
                state = OpportunityState.DISCOVERED
        else:
            state = state_val

        return cls(
            id=data.get("id") or f"opp_{uuid.uuid4().hex[:10]}",
            target=data.get("target", ""),
            asset_id=data.get("asset_id"),
            endpoint=data.get("endpoint", ""),
            protocol=data.get("protocol", "http"),
            service=data.get("service", "http"),
            technology=data.get("technology"),
            parameter=data.get("parameter"),
            artifact=data.get("artifact"),
            hypothesis=data.get("hypothesis", ""),
            attack_type=data.get("attack_type", "general"),
            prerequisites=data.get("prerequisites", []),
            confidence=float(data.get("confidence", 0.5)),
            priority=int(data.get("priority", 50)),
            evidence=data.get("evidence", {}),
            state=state,
            metadata=data.get("metadata", {}),
            created_at=float(data.get("created_at", time.time())),
            updated_at=float(data.get("updated_at", time.time())),
        )


class OpportunityBus:
    """Thread-safe & asyncio-safe event-driven priority bus for attack opportunities."""

    def __init__(self, max_concurrency_per_host: int = 5, *, use_distributed: bool = True, max_opportunities: int = 2000, scan_id: str | None = None) -> None:
        self.max_concurrency_per_host = max_concurrency_per_host
        self.use_distributed = use_distributed
        self.max_opportunities = max(1, max_opportunities)
        self.scan_id = scan_id
        self._queue: asyncio.PriorityQueue[Tuple[int, float, str, AttackOpportunity]] = asyncio.PriorityQueue()
        self._seen_fingerprints: Set[str] = set()
        self._opportunities: Dict[str, AttackOpportunity] = {}
        self._in_flight: Dict[str, AttackOpportunity] = {}
        self._host_semaphores: Dict[str, asyncio.Semaphore] = {}
        self._subscribers: Dict[str, List[Callable[[AttackOpportunity], Any]]] = {}
        self._lock = asyncio.Lock()
        self._stats = {
            "total_published": 0,
            "total_deduplicated": 0,
            "total_completed": 0,
            "total_confirmed": 0,
            "total_exploited": 0,
        }

    def _get_host_semaphore(self, host: str) -> asyncio.Semaphore:
        if host not in self._host_semaphores:
            self._host_semaphores[host] = asyncio.Semaphore(self.max_concurrency_per_host)
        return self._host_semaphores[host]

    async def publish(self, opportunity: AttackOpportunity) -> bool:
        """Publishes an opportunity to the bus. Returns True if accepted, False if duplicate."""
        if self.scan_id:
            if opportunity.metadata.get("scan_id") not in {None, self.scan_id}:
                return False
            opportunity.metadata["scan_id"] = self.scan_id
        fp = opportunity.fingerprint()
        
        # Redis distributed queue check
        from app.orchestration.distributed_queue import distributed_queue
        if self.use_distributed and distributed_queue.use_redis:
            stream_name = f"scan.{opportunity.attack_type}"
            if stream_name not in distributed_queue.STREAM_NAMES:
                stream_name = "scan.validation"
            
            msg_id = await distributed_queue.enqueue(
                stream_name=stream_name,
                payload=opportunity.to_dict(),
                idempotency_key=fp,
                priority=opportunity.priority,
            )
            if not msg_id:
                self._stats["total_deduplicated"] += 1
                logger.debug("Deduplicated opportunity via Redis: %s (%s)", opportunity.id, fp)
                return False
                
            async with self._lock:
                opportunity.state = OpportunityState.QUEUED
                opportunity.updated_at = time.time()
                self._opportunities[opportunity.id] = opportunity
                self._stats["total_published"] += 1
                
            logger.info("Published opportunity [%s] to Redis stream %s", opportunity.id, stream_name)
            await self._notify_subscribers("opportunity.queued", opportunity)
            return True

        async with self._lock:
            if len(self._opportunities) >= self.max_opportunities:
                logger.warning("Opportunity budget reached; additional candidates require a separate reviewed run")
                return False
            if fp in self._seen_fingerprints:
                self._stats["total_deduplicated"] += 1
                logger.debug("Deduplicated opportunity: %s (%s)", opportunity.id, fp)
                return False

            self._seen_fingerprints.add(fp)
            opportunity.state = OpportunityState.QUEUED
            opportunity.updated_at = time.time()
            self._opportunities[opportunity.id] = opportunity
            self._stats["total_published"] += 1

            # PriorityQueue sorts ascending: invert priority so 100 comes first (-priority)
            entry = (-opportunity.priority, opportunity.created_at, opportunity.id, opportunity)
            await self._queue.put(entry)

        logger.info(
            "Published opportunity [%s] %s on %s (Priority: %d)",
            opportunity.attack_type,
            opportunity.hypothesis[:50],
            opportunity.target or opportunity.endpoint,
            opportunity.priority,
        )
        await self._notify_subscribers("opportunity.queued", opportunity)
        return True

    async def publish_batch(self, opportunities: List[AttackOpportunity]) -> int:
        """Publishes a batch of opportunities. Returns count of newly accepted opportunities."""
        accepted = 0
        for opp in opportunities:
            if await self.publish(opp):
                accepted += 1
        return accepted

    async def get_next(self, timeout: Optional[float] = None) -> Optional[AttackOpportunity]:
        """Fetches the next highest priority opportunity, bounded by optional timeout."""
        from app.orchestration.distributed_queue import distributed_queue
        if self.use_distributed and distributed_queue.use_redis:
            try:
                # Poll streams in logical priority order
                streams_to_check = ["scan.validation", "scan.crawler", "scan.web", "scan.discovery"]
                for stream in streams_to_check:
                    tasks = await distributed_queue.claim_tasks(
                        stream_name=stream,
                        group_name="bughunter_workers",
                        consumer_name="worker_api",
                        count=1,
                    )
                    if tasks:
                        task = tasks[0]
                        opp = AttackOpportunity.from_dict(task["payload"])
                        opp.metadata["redis_message_id"] = task["message_id"]
                        opp.metadata["redis_stream"] = stream
                        
                        async with self._lock:
                            opp.state = OpportunityState.TESTING
                            opp.updated_at = time.time()
                            self._opportunities[opp.id] = opp
                            self._in_flight[opp.id] = opp
                            
                        await self._notify_subscribers("opportunity.started", opp)
                        return opp
            except Exception as e:
                logger.error("Error claiming tasks from Redis stream: %s", e)

        # Fallback to local Queue
        try:
            if timeout is not None:
                item = await asyncio.wait_for(self._queue.get(), timeout=timeout)
            else:
                item = await self._queue.get()

            _, _, opp_id, opp = item
            async with self._lock:
                opp.state = OpportunityState.TESTING
                opp.updated_at = time.time()
                self._in_flight[opp_id] = opp

            await self._notify_subscribers("opportunity.started", opp)
            return opp
        except asyncio.TimeoutError:
            return None
        except Exception as e:
            logger.error("Error getting next opportunity: %s", e)
            return None

    def task_done(self) -> None:
        """Signals to the queue that a previously popped task is complete."""
        try:
            self._queue.task_done()
        except ValueError:
            pass

    async def update_state(
        self,
        opportunity_id: str,
        new_state: OpportunityState,
        evidence: Optional[Dict[str, Any]] = None,
        message: str = "",
    ) -> None:
        """Updates the state and evidence of an opportunity."""
        async with self._lock:
            opp = self._opportunities.get(opportunity_id)
            if not opp:
                return

            opp.state = new_state
            opp.updated_at = time.time()
            if evidence:
                opp.evidence.update(evidence)

            if new_state in (
                OpportunityState.CONFIRMED,
                OpportunityState.EXPLOITED,
                OpportunityState.BLOCKED,
                OpportunityState.INCONCLUSIVE,
                OpportunityState.REJECTED,
            ):
                self._in_flight.pop(opportunity_id, None)
                self._stats["total_completed"] += 1
                if new_state == OpportunityState.CONFIRMED:
                    self._stats["total_confirmed"] += 1
                elif new_state == OpportunityState.EXPLOITED:
                    self._stats["total_exploited"] += 1

                # ACK task in Redis Streams if registered
                if opp.metadata.get("redis_message_id") and opp.metadata.get("redis_stream"):
                    try:
                        from app.orchestration.distributed_queue import distributed_queue
                        await distributed_queue.ack(
                            stream_name=opp.metadata["redis_stream"],
                            group_name="bughunter_workers",
                            message_id=opp.metadata["redis_message_id"],
                        )
                    except Exception as ack_err:
                        logger.warning("Failed to XACK Redis stream task: %s", ack_err)

        logger.info(
            "Opportunity [%s] transitioned to %s: %s",
            opportunity_id,
            new_state.value,
            message or opp.hypothesis[:40],
        )
        await self._notify_subscribers(f"opportunity.{new_state.value.lower()}", opp)

    def get_opportunity(self, opportunity_id: str) -> Optional[AttackOpportunity]:
        return self._opportunities.get(opportunity_id)

    def get_opportunities_by_state(self, state: OpportunityState) -> List[AttackOpportunity]:
        return [o for o in self._opportunities.values() if o.state == state]

    def get_all_opportunities(self) -> List[AttackOpportunity]:
        return list(self._opportunities.values())

    def get_in_flight(self) -> List[AttackOpportunity]:
        return list(self._in_flight.values())

    def get_queue_size(self) -> int:
        return self._queue.qsize()

    def get_metrics(self) -> Dict[str, Any]:
        return {
            "queue_size": self._queue.qsize(),
            "in_flight_count": len(self._in_flight),
            "total_tracked": len(self._opportunities),
            "stats": dict(self._stats),
            "states_breakdown": {
                s.value: len([o for o in self._opportunities.values() if o.state == s])
                for s in OpportunityState
            },
        }

    def subscribe(self, event_name: str, callback: Callable[[AttackOpportunity], Any]) -> None:
        if event_name not in self._subscribers:
            self._subscribers[event_name] = []
        self._subscribers[event_name].append(callback)

    async def _notify_subscribers(self, event_name: str, opp: AttackOpportunity) -> None:
        callbacks = self._subscribers.get(event_name, []) + self._subscribers.get("*", [])
        for cb in callbacks:
            try:
                res = cb(opp)
                if asyncio.iscoroutine(res):
                    asyncio.create_task(res)
            except Exception as e:
                logger.error("Error in opportunity subscriber for %s: %s", event_name, e)

    def clear(self) -> None:
        """Resets the opportunity bus."""
        while not self._queue.empty():
            try:
                self._queue.get_nowait()
                self._queue.task_done()
            except Exception:
                break
        self._seen_fingerprints.clear()
        self._opportunities.clear()
        self._in_flight.clear()
        self._host_semaphores.clear()
        self._stats = {
            "total_published": 0,
            "total_deduplicated": 0,
            "total_completed": 0,
            "total_confirmed": 0,
            "total_exploited": 0,
        }


opportunity_bus = OpportunityBus()
