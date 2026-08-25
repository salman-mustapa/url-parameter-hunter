"""Intelligence Adapter (CVE, TTP, Secrets, Attack Graph) (V8 §8)."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Set

from app.adapters.base.base_adapter import BaseAdapter
from app.intelligence.cve import CveIntelligence
from app.intelligence.secrets import secret_scanner
from app.intelligence.ttp import TtpEngine

logger = logging.getLogger("adapters.intelligence")


class IntelligenceAdapter(BaseAdapter):
    name: str = "intelligence_adapter"
    version: str = "8.0.0"
    capabilities: Set[str] = {"cve", "ttp"}

    async def healthcheck(self) -> bool:
        return True

    async def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        task_type = task.get("type", "cve")
        data = task.get("data", {})

        result: Dict[str, Any] = {
            "type": task_type,
            "correlations": [],
        }

        if task_type == "cve":
            tech_name = data.get("technology", "")
            version = data.get("version", "")
            result["correlations"] = CveIntelligence.correlate_vulnerabilities(tech_name, version)
        elif task_type == "ttp":
            vuln_type = data.get("vuln_type", "")
            result["correlations"] = TtpEngine.map_technique(vuln_type)
        elif task_type == "secrets":
            text = data.get("text", "")
            result["correlations"] = secret_scanner.scan_text(text)

        return result

    async def normalize(self, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "adapter": self.name,
            "type": raw_result.get("type"),
            "matches_count": len(raw_result.get("correlations", [])),
            "matches": raw_result.get("correlations", []),
        }
