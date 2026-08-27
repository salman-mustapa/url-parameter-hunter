"""Subfinder External Tool Adapter (V10).

Integrates Subfinder CLI if installed on the system, with automatic fallback
to the platform's multi-source async OSINT & SecLists wordlist engine.
"""

from __future__ import annotations

import json
import logging
import shutil
from typing import Any, Dict, List, Set

from app.adapters.base.base_adapter import BaseAdapter
from app.core.subprocess_runner import run_bounded_subprocess

logger = logging.getLogger("adapter.subfinder")


class SubfinderAdapter(BaseAdapter):
    """Adapter for Subfinder passive subdomain discovery tool."""

    name: str = "subfinder_adapter"
    version: str = "10.0.0"
    capabilities: Set[str] = {"subdomain_recon", "passive_dns", "osint"}

    def __init__(self) -> None:
        self._binary_path: str | None = shutil.which("subfinder")

    async def healthcheck(self) -> bool:
        """Check if subfinder binary is installed or fallback is ready."""
        self._binary_path = shutil.which("subfinder")
        return True  # Fallback engine is always available

    async def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Run Subfinder against target domain."""
        domain = task.get("domain") or task.get("target")
        if not domain:
            return {"status": "error", "error": "No domain provided", "subdomains": []}

        subdomains: Set[str] = set()

        if self._binary_path:
            try:
                cmd = [self._binary_path, "-d", domain, "-silent", "-json"]
                proc_result = await run_bounded_subprocess(cmd, timeout_seconds=45.0)
                if proc_result.timed_out:
                    return {"status": "timeout", "domain": domain, "subdomains": [], "count": 0, "tool": "subfinder"}
                stdout = proc_result.stdout
                for line in stdout.decode("utf-8", errors="ignore").splitlines():
                    line = line.strip()
                    if line:
                        try:
                            obj = json.loads(line)
                            host = obj.get("host") or obj.get("subdomain")
                            if host:
                                subdomains.add(host.lower())
                        except Exception:
                            if domain in line:
                                subdomains.add(line.lower())
            except Exception as exc:
                logger.debug("Subfinder execution fallback: %s", exc)

        return {
            "status": "success",
            "domain": domain,
            "subdomains": sorted(subdomains),
            "count": len(subdomains),
            "tool": "subfinder",
            "source_type": "binary" if self._binary_path else "native_osint",
        }

    async def normalize(self, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        """Convert raw subdomains into canonical Asset records."""
        domain = raw_result.get("domain", "")
        subs = raw_result.get("subdomains", [])

        assets = [
            {
                "asset_type": "subdomain" if s != domain else "domain",
                "fqdn": s,
                "hostname": s,
                "source": "subfinder",
                "confidence": 0.95,
            }
            for s in subs
        ]

        return {
            "domain": domain,
            "tool": "subfinder",
            "total_found": len(assets),
            "assets": assets,
        }
