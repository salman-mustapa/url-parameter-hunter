"""Base Worker Class (V8 §42)."""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

logger = logging.getLogger("workers.base")


class BaseWorker(ABC):
    """Abstract Base Worker Class for all 13 worker types (V8 §42)."""

    worker_class: str = "base-worker"

    def __init__(self, worker_id: str) -> None:
        self.worker_id = worker_id
        self.is_running = False

    @abstractmethod
    async def process_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        ...

    def get_status(self) -> Dict[str, Any]:
        return {
            "worker_id": self.worker_id,
            "worker_class": self.worker_class,
            "is_running": self.is_running,
        }
