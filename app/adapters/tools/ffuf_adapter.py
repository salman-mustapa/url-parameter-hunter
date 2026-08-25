"""FFUF Tool Adapter (V10)."""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import tempfile
from typing import Any, Dict, List, Set

from app.adapters.base.base_adapter import BaseAdapter

logger = logging.getLogger("adapter.ffuf")


class FfufAdapter(BaseAdapter):
    """Adapter for FFUF high-speed fuzzer."""

    name: str = "ffuf_adapter"
    version: str = "10.0.0"
    capabilities: Set[str] = {"path_fuzzing", "parameter_fuzzing", "vhost_fuzzing"}

    def __init__(self) -> None:
        self._binary_path: str | None = shutil.which("ffuf")

    async def healthcheck(self) -> bool:
        self._binary_path = shutil.which("ffuf")
        return True

    async def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        target_url = task.get("url") or task.get("target_url")
        wordlist = task.get("wordlist")

        if not target_url:
            return {"status": "error", "error": "No URL provided", "results": []}

        results: List[Dict[str, Any]] = []

        if self._binary_path and wordlist:
            fuzz_url = target_url.rstrip("/") + "/FUZZ" if "FUZZ" not in target_url else target_url
            temp_file = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
            temp_file.close()

            try:
                cmd = [
                    self._binary_path,
                    "-u", fuzz_url,
                    "-w", wordlist,
                    "-o", temp_file.name,
                    "-of", "json",
                    "-s",
                    "-t", "20",
                    "-mc", "200,204,301,302,307,401,403",
                ]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await asyncio.wait_for(proc.communicate(), timeout=45.0)

                with open(temp_file.name, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)
                    for r in data.get("results", []):
                        results.append({
                            "url": r.get("url"),
                            "status": r.get("status"),
                            "length": r.get("length"),
                            "words": r.get("words"),
                            "input": r.get("input", {}).get("FUZZ"),
                        })
            except Exception as exc:
                logger.debug("FFUF execution fallback: %s", exc)
            finally:
                shutil.os.unlink(temp_file.name)

        return {
            "status": "success",
            "target_url": target_url,
            "results": results,
            "count": len(results),
            "tool": "ffuf",
        }

    async def normalize(self, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "target_url": raw_result.get("target_url"),
            "tool": "ffuf",
            "endpoints": [
                {"url": r.get("url"), "status_code": r.get("status"), "source": "ffuf"}
                for r in raw_result.get("results", [])
            ],
        }
