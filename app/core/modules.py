"""Security Module Plugin Architecture (§106).

Defines the SecurityModule base class so that all assessment
modules have a uniform interface. Core orchestrator dispatches
to modules without knowing implementation details.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("modules")


@dataclass
class ModuleContext:
    """Context passed to every module operation."""
    scan_id: str
    asset_id: str
    hostname: str
    ip: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    parameters: List[dict] = field(default_factory=list)
    auth_context: Optional[str] = None
    profile: str = "standard"
    scope: Optional[Any] = None
    db: Optional[Any] = None
    extra: Dict[str, Any] = field(default_factory=dict)


class SecurityModule(ABC):
    """Base class for all security assessment modules (§106).

    Every module implements:
    - discover() — find additional assets/endpoints related to this module
    - assess() — passive/active analysis
    - validate() — controlled security testing
    - collect_evidence() — gather evidence for findings

    Module metadata:
    - id: unique identifier
    - name: human-readable name
    - category: discovery|network|web|browser|intelligence|validation|reporting
    - applicable_to: list of asset_types this module applies to
    """

    id: str = ""
    name: str = ""
    category: str = ""
    applicable_to: List[str] = []

    @abstractmethod
    async def discover(self, context: ModuleContext) -> List[dict]:
        """Find additional assets/endpoints."""
        ...

    @abstractmethod
    async def assess(self, context: ModuleContext) -> List[dict]:
        """Perform passive/active analysis."""
        ...

    @abstractmethod
    async def validate(self, context: ModuleContext) -> List[dict]:
        """Run controlled security tests."""
        ...

    @abstractmethod
    async def collect_evidence(self, context: ModuleContext) -> List[dict]:
        """Gather structured evidence for findings."""
        ...

    def is_applicable(self, context: ModuleContext) -> bool:
        """Check if this module should run for the given context."""
        return True


class ModuleRegistry:
    """Registry for all security modules."""

    def __init__(self) -> None:
        self._modules: Dict[str, SecurityModule] = {}

    def register(self, module: SecurityModule) -> None:
        self._modules[module.id] = module
        logger.info("Module registered: %s (%s)", module.id, module.name)

    def get(self, module_id: str) -> Optional[SecurityModule]:
        return self._modules.get(module_id)

    def list_modules(self) -> List[Dict[str, str]]:
        return [
            {"id": m.id, "name": m.name, "category": m.category}
            for m in self._modules.values()
        ]

    def get_applicable(self, context: ModuleContext) -> List[SecurityModule]:
        """Get all modules applicable to a given context."""
        return [m for m in self._modules.values() if m.is_applicable(context)]

    def get_by_category(self, category: str) -> List[SecurityModule]:
        return [m for m in self._modules.values() if m.category == category]


# Global registry
module_registry = ModuleRegistry()
