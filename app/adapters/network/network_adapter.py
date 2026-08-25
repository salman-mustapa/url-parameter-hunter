"""Network Assessment Adapter (TLS, SSH, RDP, Service Protocols) (V8 §8)."""

from __future__ import annotations

import logging
from typing import Any, Dict, Set

from app.adapters.base.base_adapter import BaseAdapter
from app.network.rdp import RdpAssessment
from app.network.ssh import SshAssessment
from app.network.tls import TlsAssessment

logger = logging.getLogger("adapters.network")


class NetworkAdapter(BaseAdapter):
    name: str = "network_adapter"
    version: str = "8.0.0"
    capabilities: Set[str] = {"network"}

    async def healthcheck(self) -> bool:
        return True

    async def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        target = task.get("target", "")
        service_type = task.get("service_type", "tls")
        port_num = task.get("port")

        raw_result: Dict[str, Any] = {
            "target": target,
            "service_type": service_type,
            "port": port_num,
            "assessment": {},
        }

        try:
            if service_type in ("tls", "https", "ssl"):
                raw_result["assessment"] = await TlsAssessment.analyze(target, port=port_num or 443)
            elif service_type == "ssh":
                raw_result["assessment"] = await SshAssessment.analyze(target, port=port_num or 22)
            elif service_type in ("rdp", "ms-wbt-server"):
                raw_result["assessment"] = await RdpAssessment.analyze(target, port=port_num or 3389)
        except Exception as exc:
            logger.warning("Network adapter execution warning on %s:%s - %s", target, port_num, exc)
            raw_result["error"] = str(exc)

        return raw_result

    async def normalize(self, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        assessment = raw_result.get("assessment", {})
        return {
            "adapter": self.name,
            "target": raw_result.get("target"),
            "service_type": raw_result.get("service_type"),
            "port": raw_result.get("port"),
            "is_secure": assessment.get("is_secure", True),
            "findings_count": len(assessment.get("findings", [])),
            "assessment": assessment,
        }
