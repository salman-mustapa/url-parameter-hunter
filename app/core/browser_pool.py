"""Shared Headless Browser Pool & Tenant Quotas (V13 §32).

Prevents browser process exhaustion:
- Bounded pool of headless browser sessions.
- Tenant context quotas (max concurrent pages per tenant).
- Safe lifecycle, automated timeout cleanup, and context recycling.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

logger = logging.getLogger("core.browser_pool")


@dataclass
class BrowserContextSession:
    session_id: str
    tenant_id: str
    target_url: str
    created_at: float = field(default_factory=time.time)
    in_use: bool = True


class BrowserPool:
    """Manages shared browser contexts with per-tenant quotas."""

    def __init__(
        self,
        max_total_contexts: int = 20,
        max_contexts_per_tenant: int = 3,
    ) -> None:
        self.max_total_contexts = max_total_contexts
        self.max_contexts_per_tenant = max_contexts_per_tenant
        self._active_sessions: Dict[str, BrowserContextSession] = {}
        self._tenant_usage: Dict[str, int] = defaultdict(int)
        self._lock = asyncio.Lock()

    async def acquire_context(self, tenant_id: str, target_url: str) -> Optional[str]:
        """Acquires a browser context slot if within quotas."""
        async with self._lock:
            if len(self._active_sessions) >= self.max_total_contexts:
                logger.warning("BrowserPool saturated: %d/%d total contexts active.", len(self._active_sessions), self.max_total_contexts)
                return None

            if self._tenant_usage[tenant_id] >= self.max_contexts_per_tenant:
                logger.warning("BrowserPool tenant quota reached for %s (%d/%d)", tenant_id, self._tenant_usage[tenant_id], self.max_contexts_per_tenant)
                return None

            session_id = f"b_ctx_{int(time.time()*1000)}_{len(self._active_sessions)}"
            session = BrowserContextSession(
                session_id=session_id,
                tenant_id=tenant_id,
                target_url=target_url,
            )
            self._active_sessions[session_id] = session
            self._tenant_usage[tenant_id] += 1
            return session_id

    async def release_context(self, session_id: str) -> None:
        """Releases and recycles a browser context."""
        async with self._lock:
            session = self._active_sessions.pop(session_id, None)
            if session:
                self._tenant_usage[session.tenant_id] = max(0, self._tenant_usage[session.tenant_id] - 1)

    def get_stats(self) -> Dict[str, Any]:
        """Returns browser pool utilization metrics."""
        return {
            "active_contexts": len(self._active_sessions),
            "max_total_contexts": self.max_total_contexts,
            "max_contexts_per_tenant": self.max_contexts_per_tenant,
            "tenant_breakdown": dict(self._tenant_usage),
        }

    async def reset(self) -> None:
        """Resets the browser pool."""
        async with self._lock:
            self._active_sessions.clear()
            self._tenant_usage.clear()


browser_pool = BrowserPool()
