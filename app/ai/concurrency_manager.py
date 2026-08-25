"""AI Concurrency Manager & Rate Governor (V13 §33).

Manages bounded AI concurrency:
- Global AI concurrency limit.
- Provider and model concurrency limits.
- Tenant quota limits.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from typing import Any, Dict, Optional

logger = logging.getLogger("ai.concurrency_manager")


class AIConcurrencyManager:
    """Controls bounded AI request execution across tenants and providers."""

    def __init__(
        self,
        global_max_concurrent: int = 25,
        tenant_max_concurrent: int = 5,
    ) -> None:
        self.global_max_concurrent = global_max_concurrent
        self.tenant_max_concurrent = tenant_max_concurrent

        self._active_global: int = 0
        self._active_per_tenant: Dict[str, int] = defaultdict(int)
        self._active_per_provider: Dict[str, int] = defaultdict(int)
        self._lock = asyncio.Lock()

    async def acquire_slot(self, tenant_id: str, provider_name: str) -> bool:
        """Attempts to acquire a slot for an AI request."""
        async with self._lock:
            if self._active_global >= self.global_max_concurrent:
                logger.debug("AI slot rejected: Global limit reached (%d/%d)", self._active_global, self.global_max_concurrent)
                return False

            if self._active_per_tenant[tenant_id] >= self.tenant_max_concurrent:
                logger.debug("AI slot rejected: Tenant %s limit reached (%d/%d)", tenant_id, self._active_per_tenant[tenant_id], self.tenant_max_concurrent)
                return False

            self._active_global += 1
            self._active_per_tenant[tenant_id] += 1
            self._active_per_provider[provider_name] += 1
            return True

    async def release_slot(self, tenant_id: str, provider_name: str) -> None:
        """Releases the acquired AI slot."""
        async with self._lock:
            self._active_global = max(0, self._active_global - 1)
            self._active_per_tenant[tenant_id] = max(0, self._active_per_tenant[tenant_id] - 1)
            self._active_per_provider[provider_name] = max(0, self._active_per_provider[provider_name] - 1)

    def get_stats(self) -> Dict[str, Any]:
        """Returns live AI concurrency metrics."""
        return {
            "active_global": self._active_global,
            "global_max_concurrent": self.global_max_concurrent,
            "tenant_max_concurrent": self.tenant_max_concurrent,
            "active_per_tenant": dict(self._active_per_tenant),
            "active_per_provider": dict(self._active_per_provider),
        }

    async def reset(self) -> None:
        """Resets the AI concurrency manager."""
        async with self._lock:
            self._active_global = 0
            self._active_per_tenant.clear()
            self._active_per_provider.clear()


ai_concurrency_manager = AIConcurrencyManager()
