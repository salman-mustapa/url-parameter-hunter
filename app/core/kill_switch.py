"""Global & Per-Module Granular Kill Switch (V8 §43).

Enforces immediate cancellation:
- Global: STOP CAMPAIGN
- Per-Module:
  - STOP NETWORK
  - STOP CRAWLER
  - STOP BROWSER
  - STOP VALIDATION
  - STOP AI
  - STOP LAB SIMULATION

Workers and async tasks check cancellation state frequently during pipeline execution.
"""

from __future__ import annotations

import logging
from typing import Dict, Optional, Set

logger = logging.getLogger("core.kill_switch")


class KillSwitchManager:
    """Central manager for global and module-level kill switches (V8 §43)."""

    def __init__(self) -> None:
        self._global_stops: Set[str] = set()  # scan_ids stopped globally
        self._module_stops: Dict[str, Set[str]] = {}  # scan_id -> set of stopped module categories

    def stop_campaign(self, scan_id: str) -> None:
        """Triggers global kill switch for an entire campaign."""
        self._global_stops.add(scan_id)
        logger.warning("GLOBAL KILL SWITCH ACTIVATED for campaign %s", scan_id)

    def stop_module(self, scan_id: str, module_category: str) -> None:
        """Triggers granular kill switch for a specific module category."""
        if scan_id not in self._module_stops:
            self._module_stops[scan_id] = set()
        norm_mod = module_category.lower().strip()
        self._module_stops[scan_id].add(norm_mod)
        logger.warning("MODULE KILL SWITCH ACTIVATED: [Scan: %s, Module: %s]", scan_id, norm_mod)

    def is_stopped(self, scan_id: str, module_category: Optional[str] = None) -> bool:
        """Checks if a campaign or specific module has been instructed to halt."""
        if scan_id in self._global_stops:
            return True
        if module_category and scan_id in self._module_stops:
            norm_mod = module_category.lower().strip()
            if norm_mod in self._module_stops[scan_id]:
                return True
        return False

    def reset(self, scan_id: str) -> None:
        """Resets kill switch state upon campaign restart/retest."""
        self._global_stops.discard(scan_id)
        self._module_stops.pop(scan_id, None)


kill_switch_manager = KillSwitchManager()
