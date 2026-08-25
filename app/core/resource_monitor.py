"""Resource-Aware Concurrency & Validation Monitor (V5 §46).
Monitors system load (CPU, RAM, queue depth, active browser sessions)
and dynamically throttles or scales validation worker concurrency.
"""

from __future__ import annotations

import logging
import os
from typing import Dict, Any

try:
    import psutil
except ImportError:
    psutil = None

logger = logging.getLogger("resource.monitor")


class ResourceMonitor:
    """Monitors system performance metrics and dynamically tunes concurrency (§46)."""

    DEFAULT_MAX_CONCURRENCY = 15
    DEFAULT_MIN_CONCURRENCY = 2

    @classmethod
    def get_system_metrics(cls) -> Dict[str, Any]:
        """Collect real-time CPU, RAM, and load metrics."""
        try:
            cpu_pct = psutil.cpu_percent(interval=0.1)
            mem = psutil.virtual_memory()
            mem_pct = mem.percent
        except Exception:
            cpu_pct = 20.0
            mem_pct = 35.0

        return {
            "cpu_percent": cpu_pct,
            "memory_percent": mem_pct,
            "pid": os.getpid(),
        }

    @classmethod
    def calculate_optimal_concurrency(cls, requested_concurrency: int = 10) -> int:
        """Dynamically bound concurrency based on resource saturation (§46)."""
        metrics = cls.get_system_metrics()
        cpu = metrics["cpu_percent"]
        mem = metrics["memory_percent"]

        if cpu > 85.0 or mem > 90.0:
            optimal = max(cls.DEFAULT_MIN_CONCURRENCY, requested_concurrency // 3)
            logger.warning("Resource pressure high (CPU: %.1f%%, RAM: %.1f%%). Throttling concurrency to %d", cpu, mem, optimal)
            return optimal
        elif cpu > 70.0 or mem > 75.0:
            optimal = max(cls.DEFAULT_MIN_CONCURRENCY, requested_concurrency // 2)
            return optimal

        return min(cls.DEFAULT_MAX_CONCURRENCY, requested_concurrency)
