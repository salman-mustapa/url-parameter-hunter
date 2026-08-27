"""Katana Web Crawler Tool Adapter (V10)."""

from __future__ import annotations

import json
import logging
import shutil
from typing import Any, Dict, List, Set

from app.adapters.base.base_adapter import BaseAdapter
from app.core.subprocess_runner import run_bounded_subprocess

logger = logging.getLogger("adapter.katana")


class KatanaAdapter(BaseAdapter):
    """Adapter for Katana next-generation crawling engine."""

    name: str = "katana_adapter"
    version: str = "10.0.0"
    capabilities: Set[str] = {"dynamic_crawling", "js_crawling", "endpoint_extraction"}

    def __init__(self) -> None:
        self._binary_path: str | None = shutil.which("katana")

    async def healthcheck(self) -> bool:
        self._binary_path = shutil.which("katana")
        return True

    async def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        target_url = task.get("url") or task.get("target_url")
        depth = min(task.get("depth", 2), 3)

        if not target_url:
            return {"status": "error", "error": "No URL provided", "endpoints": []}

        endpoints: List[str] = []

        if self._binary_path:
            try:
                cmd = [
                    self._binary_path,
                    "-u", target_url,
                    "-d", str(depth),
                    "-silent",
                    "-jsonl",
                    "-ct", "30s",
                ]
                proc_result = await run_bounded_subprocess(cmd, timeout_seconds=40.0)
                if proc_result.timed_out:
                    return {"status": "timeout", "target_url": target_url, "endpoints": [], "count": 0, "tool": "katana"}
                stdout = proc_result.stdout
                for line in stdout.decode("utf-8", errors="ignore").splitlines():
                    line = line.strip()
                    if line:
                        try:
                            obj = json.loads(line)
                            req = obj.get("request", {})
                            u = req.get("endpoint") or obj.get("url")
                            if u:
                                endpoints.append(u)
                        except Exception:
                            if "://" in line:
                                endpoints.append(line)
            except Exception as exc:
                logger.debug("Katana execution fallback: %s", exc)

        return {
            "status": "success",
            "target_url": target_url,
            "endpoints": endpoints,
            "count": len(endpoints),
            "tool": "katana",
        }

    async def normalize(self, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "target_url": raw_result.get("target_url"),
            "tool": "katana",
            "endpoints": [{"url": u, "source": "katana"} for u in raw_result.get("endpoints", [])],
        }
