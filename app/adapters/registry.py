"""Central Adapter Registry & Dispatcher (V8 §8)."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.adapters.base.base_adapter import BaseAdapter
from app.adapters.discovery.discovery_adapter import DiscoveryAdapter
from app.adapters.intelligence.intelligence_adapter import IntelligenceAdapter
from app.adapters.network.network_adapter import NetworkAdapter
from app.adapters.tools.dirsearch_adapter import DirsearchAdapter
from app.adapters.tools.ffuf_adapter import FfufAdapter
from app.adapters.tools.gau_adapter import GauAdapter
from app.adapters.tools.katana_adapter import KatanaAdapter
from app.adapters.tools.nmap_adapter import NmapAdapter
from app.adapters.tools.nuclei_adapter import NucleiAdapter
from app.adapters.tools.subfinder_adapter import SubfinderAdapter
from app.adapters.tools.trufflehog_adapter import TruffleHogAdapter
from app.adapters.validation.validation_adapter import ValidationAdapter
from app.adapters.web.web_adapter import WebAdapter

logger = logging.getLogger("adapters.registry")


class AdapterRegistry:
    """Manages all V10 core and tool adapters and routes execution with healthchecks."""

    def __init__(self) -> None:
        self._adapters: Dict[str, BaseAdapter] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        # Core Platform Adapters
        self.register(DiscoveryAdapter())
        self.register(NetworkAdapter())
        self.register(WebAdapter())
        self.register(IntelligenceAdapter())
        self.register(ValidationAdapter())

        # Integrated Tool Adapters (V10)
        self.register(DirsearchAdapter())
        self.register(SubfinderAdapter())
        self.register(FfufAdapter())
        self.register(KatanaAdapter())
        self.register(NmapAdapter())
        self.register(NucleiAdapter())
        self.register(GauAdapter())
        self.register(TruffleHogAdapter())

    def register(self, adapter: BaseAdapter) -> None:
        self._adapters[adapter.name] = adapter
        logger.info("Registered adapter: %s (v%s, capabilities: %s)", adapter.name, adapter.version, adapter.capabilities)

    def get(self, adapter_name: str) -> Optional[BaseAdapter]:
        return self._adapters.get(adapter_name)

    async def execute_adapter(self, adapter_name: str, task: Dict[str, Any]) -> Dict[str, Any]:
        adapter = self.get(adapter_name)
        if not adapter:
            raise ValueError(f"Adapter not found: {adapter_name}")

        is_healthy = await adapter.healthcheck()
        if not is_healthy:
            raise RuntimeError(f"Adapter {adapter_name} failed healthcheck")

        raw_result = await adapter.execute(task)
        return await adapter.normalize(raw_result)

    def list_adapters(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": a.name,
                "version": a.version,
                "capabilities": list(a.capabilities),
            }
            for a in self._adapters.values()
        ]


adapter_registry = AdapterRegistry()
