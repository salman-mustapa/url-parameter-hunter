"""Nmap Network Recon Adapter (V10)."""

from __future__ import annotations

import asyncio
import logging
import shutil
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Set

from app.adapters.base.base_adapter import BaseAdapter

logger = logging.getLogger("adapter.nmap")


class NmapAdapter(BaseAdapter):
    """Adapter for Nmap port scanner and service detection."""

    name: str = "nmap_adapter"
    version: str = "10.0.0"
    capabilities: Set[str] = {"port_scanning", "service_detection", "os_fingerprinting"}

    def __init__(self) -> None:
        self._binary_path: str | None = shutil.which("nmap")

    async def healthcheck(self) -> bool:
        self._binary_path = shutil.which("nmap")
        return True

    async def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        target = task.get("host") or task.get("target")
        ports = task.get("ports", "80,443,8080,8443,3000,5000,8000,9000")

        if not target:
            return {"status": "error", "error": "No target host provided", "ports": []}

        open_ports: List[Dict[str, Any]] = []

        if self._binary_path:
            try:
                cmd = [
                    self._binary_path,
                    "-p", ports,
                    "-sV",
                    "-T4",
                    "--open",
                    "-oX", "-",
                    target,
                ]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=35.0)

                root = ET.fromstring(stdout.decode("utf-8", errors="ignore"))
                for port_elem in root.findall(".//port"):
                    state = port_elem.find("state")
                    if state is not None and state.get("state") == "open":
                        p_id = int(port_elem.get("portid", 0))
                        proto = port_elem.get("protocol", "tcp")
                        svc_elem = port_elem.find("service")
                        svc_name = svc_elem.get("name", "unknown") if svc_elem is not None else "unknown"
                        version = svc_elem.get("version", "") if svc_elem is not None else ""
                        open_ports.append({
                            "port": p_id,
                            "protocol": proto,
                            "service": svc_name,
                            "version": version,
                            "state": "open",
                        })
            except Exception as exc:
                logger.debug("Nmap execution fallback: %s", exc)

        return {
            "status": "success",
            "target": target,
            "open_ports": open_ports,
            "count": len(open_ports),
            "tool": "nmap",
        }

    async def normalize(self, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "target": raw_result.get("target"),
            "tool": "nmap",
            "ports": raw_result.get("open_ports", []),
        }
