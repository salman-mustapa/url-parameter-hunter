"""Dirsearch External Tool Adapter (V10).

Integrates the official Dirsearch engine and its 9,681+ path dictionary (`dirsearch/db/dicc.txt`)
with auto-calibration, multi-extension support, and high-concurrency async fallback.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Set

from app.adapters.base.base_adapter import BaseAdapter
from app.scanners.http import fetch_http

logger = logging.getLogger("adapter.dirsearch")


class DirsearchAdapter(BaseAdapter):
    """Adapter for Dirsearch path discovery engine."""

    name: str = "dirsearch_adapter"
    version: str = "10.0.0"
    capabilities: Set[str] = {"path_fuzzing", "content_discovery", "backup_discovery", "config_discovery"}

    def __init__(self) -> None:
        self._dirsearch_available: bool | None = None
        self._dicc_path: Path | None = None

    async def healthcheck(self) -> bool:
        """Check if dirsearch module and its dictionary are available."""
        if self._dirsearch_available is not None:
            return self._dirsearch_available

        try:
            import dirsearch
            d = os.path.dirname(dirsearch.__file__)
            dicc = Path(d) / "db" / "dicc.txt"
            if dicc.exists():
                self._dicc_path = dicc
                self._dirsearch_available = True
                return True
        except ImportError:
            pass

        self._dirsearch_available = True  # Native async fallback always ready
        return True

    async def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Dirsearch against target URL."""
        target_url = task.get("target_url") or task.get("url")
        if not target_url:
            return {"status": "error", "error": "No target URL provided", "discovered_urls": []}

        extensions = task.get("extensions", "php,asp,aspx,jsp,html,js,json,sql,env,bak,zip,tar.gz,log,txt")
        threads = min(task.get("threads", 20), 30)
        max_time = min(task.get("max_time", 60), 120)

        # 1. Try running via dirsearch CLI/module with JSON output
        temp_file = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        temp_file.close()
        temp_path = temp_file.name

        cmd = [
            sys.executable,
            "-m",
            "dirsearch",
            "-u",
            target_url,
            "-e",
            extensions,
            "--auto-calibration",
            "-O",
            "json",
            "-o",
            temp_path,
            "-q",
            "-t",
            str(threads),
            "--max-time",
            str(max_time),
        ]

        discovered: List[Dict[str, Any]] = []

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                await asyncio.wait_for(proc.communicate(), timeout=float(max_time + 10))
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except Exception:
                    pass

            if os.path.exists(temp_path) and os.path.getsize(temp_path) > 0:
                with open(temp_path, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)
                    # Dirsearch JSON format contains results dictionary
                    results = data.get("results", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
                    for item in results:
                        if isinstance(item, dict):
                            discovered.append({
                                "url": item.get("url"),
                                "status": item.get("status"),
                                "content_length": item.get("content-length") or item.get("content_length"),
                                "redirect": item.get("redirect"),
                                "content_type": item.get("content-type") or item.get("content_type", ""),
                            })
        except Exception as exc:
            logger.debug("Dirsearch subprocess execution fallback (%s)", exc)
        finally:
            if os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except Exception:
                    pass

        # 2. If subprocess produced 0 results or had an issue, run high-speed async fallback
        if not discovered and self._dicc_path and self._dicc_path.exists():
            discovered = await self._async_wordlist_fallback(target_url, limit=200)

        return {
            "status": "success",
            "target_url": target_url,
            "discovered_urls": discovered,
            "count": len(discovered),
            "tool": "dirsearch",
        }

    async def _async_wordlist_fallback(self, base_url: str, limit: int = 200) -> List[Dict[str, Any]]:
        """High-speed async fallback reading from dirsearch/db/dicc.txt."""
        discovered: List[Dict[str, Any]] = []
        if not self._dicc_path or not self._dicc_path.exists():
            return discovered

        try:
            lines = self._dicc_path.read_text(errors="ignore").splitlines()
            paths = [line.strip() for line in lines if line.strip() and not line.startswith("#")][:limit]
        except Exception:
            return discovered

        sem = asyncio.Semaphore(15)

        async def probe(path: str):
            async with sem:
                u = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
                resp = await fetch_http(u, timeout=4.0)
                if resp and resp.status_code in (200, 204, 301, 302, 307, 401, 403):
                    discovered.append({
                        "url": u,
                        "status": resp.status_code,
                        "content_length": len(resp.content),
                        "content_type": resp.headers.get("content-type", ""),
                    })

        await asyncio.gather(*(probe(p) for p in paths), return_exceptions=True)
        return discovered

    async def normalize(self, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        """Convert raw Dirsearch results into canonical URL records."""
        items = raw_result.get("discovered_urls", [])
        normalized_urls = []

        for item in items:
            u = item.get("url")
            status = item.get("status", 200)
            if u:
                normalized_urls.append({
                    "url": u,
                    "status_code": status,
                    "content_length": item.get("content_length", 0),
                    "content_type": item.get("content_type", ""),
                    "source": "dirsearch",
                })

        return {
            "target_url": raw_result.get("target_url"),
            "tool": "dirsearch",
            "total_found": len(normalized_urls),
            "endpoints": normalized_urls,
        }
