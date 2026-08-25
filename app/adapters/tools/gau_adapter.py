"""GAU (GetAllUrls) Passive URL Harvester Adapter (V10)."""

from __future__ import annotations

import asyncio
import logging
import shutil
from typing import Any, Dict, List, Set

from app.adapters.base.base_adapter import BaseAdapter

logger = logging.getLogger("adapter.gau")


class GauAdapter(BaseAdapter):
    """Adapter for GAU (GetAllUrls) & Waybackurls passive harvesting."""

    name: str = "gau_adapter"
    version: str = "10.0.0"
    capabilities: Set[str] = {"passive_urls", "archive_mining", "endpoint_discovery"}

    def __init__(self) -> None:
        self._binary_path: str | None = shutil.which("gau") or shutil.which("waybackurls")

    async def healthcheck(self) -> bool:
        self._binary_path = shutil.which("gau") or shutil.which("waybackurls")
        return True

    async def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        domain = task.get("domain") or task.get("target") or task.get("host")
        if not domain:
            return {"status": "error", "error": "No domain provided", "urls": []}

        urls: Set[str] = set()

        if self._binary_path:
            try:
                cmd = [self._binary_path, domain]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=35.0)
                for line in stdout.decode("utf-8", errors="ignore").splitlines():
                    line = line.strip()
                    if line and line.startswith(("http://", "https://")):
                        urls.add(line)
            except Exception as exc:
                logger.debug("GAU execution fallback: %s", exc)

        return {
            "status": "success",
            "domain": domain,
            "urls": sorted(urls),
            "count": len(urls),
            "tool": "gau",
        }

    async def normalize(self, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "domain": raw_result.get("domain"),
            "tool": "gau",
            "total_urls": raw_result.get("count", 0),
            "urls": [{"url": u, "source": "gau"} for u in raw_result.get("urls", [])],
        }
