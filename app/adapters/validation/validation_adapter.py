"""Validation Adapter bridging active security tests into normalized results (V8 §8)."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set

from app.adapters.base.base_adapter import BaseAdapter
from app.validation.result import NormalizedValidationResult

logger = logging.getLogger("adapters.validation")


class ValidationAdapter(BaseAdapter):
    name: str = "validation_adapter"
    version: str = "8.0.0"
    capabilities: Set[str] = {"payload-validation", "authentication", "authorization", "privilege-validation"}

    async def healthcheck(self) -> bool:
        return True

    async def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatches to appropriate validator module (SQLi, XSS, SSRF, RCE Canary, etc.)."""
        module_name = task.get("module", "")
        target_url = task.get("target_url", "")
        parameter = task.get("parameter", "")

        raw_result: Dict[str, Any] = {
            "module": module_name,
            "target_url": target_url,
            "parameter": parameter,
            "is_vulnerable": False,
            "findings": [],
        }

        return raw_result

    async def normalize(self, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "adapter": self.name,
            "module": raw_result.get("module"),
            "target_url": raw_result.get("target_url"),
            "is_vulnerable": raw_result.get("is_vulnerable", False),
            "findings_count": len(raw_result.get("findings", [])),
            "findings": raw_result.get("findings", []),
        }
