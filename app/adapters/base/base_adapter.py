"""Base Adapter Interface & Types (V8 §8).

Separates scanner/execution logic from core business and orchestration logic.
Every adapter implements:
- healthcheck(): verifies runtime dependencies/readiness
- execute(task): performs assessment or analysis
- normalize(raw_result): produces uniform structured output
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Set


class BaseAdapter(ABC):
    """Abstract Base Class for all V8 Adapters."""

    name: str = "base_adapter"
    version: str = "8.0.0"
    capabilities: Set[str] = set()

    @abstractmethod
    async def healthcheck(self) -> bool:
        """Verify underlying scanner or module is ready and healthy."""
        ...

    @abstractmethod
    async def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the requested task against the target within scope."""
        ...

    @abstractmethod
    async def normalize(self, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        """Convert raw adapter output into normalized platform data."""
        ...
