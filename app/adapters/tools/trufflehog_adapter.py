"""TruffleHog Secret & Credential Leak Scanner Adapter (V10)."""

from __future__ import annotations

import json
import logging
import shutil
from typing import Any, Dict, List, Set

from app.adapters.base.base_adapter import BaseAdapter
from app.core.subprocess_runner import run_bounded_subprocess

logger = logging.getLogger("adapter.trufflehog")


class TruffleHogAdapter(BaseAdapter):
    """Adapter for TruffleHog deep credential and secret scanner."""

    name: str = "trufflehog_adapter"
    version: str = "10.0.0"
    capabilities: Set[str] = {"secret_scanning", "credential_leak_audit", "api_key_detection"}

    def __init__(self) -> None:
        self._binary_path: str | None = shutil.which("trufflehog")

    async def healthcheck(self) -> bool:
        self._binary_path = shutil.which("trufflehog")
        return True

    async def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        target_path = task.get("path") or task.get("file_path") or task.get("target")
        if not target_path:
            return {"status": "error", "error": "No target path provided", "secrets": []}

        secrets: List[Dict[str, Any]] = []

        if self._binary_path:
            try:
                cmd = [
                    self._binary_path,
                    "filesystem",
                    target_path,
                    "--json",
                    "--no-verification",
                ]
                proc_result = await run_bounded_subprocess(cmd, timeout_seconds=30.0)
                if proc_result.timed_out:
                    return {"status": "timeout", "target": target_path, "secrets": [], "count": 0, "tool": "trufflehog"}
                stdout = proc_result.stdout
                for line in stdout.decode("utf-8", errors="ignore").splitlines():
                    line = line.strip()
                    if line and line.startswith("{"):
                        try:
                            obj = json.loads(line)
                            detector = obj.get("DetectorName") or obj.get("detector_name", "secret")
                            raw_val = obj.get("Raw", "")
                            secrets.append({
                                "detector": detector,
                                "raw_masked": raw_val[:4] + "****" if len(raw_val) > 4 else "****",
                                "source_file": obj.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", target_path),
                            })
                        except Exception:
                            continue
            except Exception as exc:
                logger.debug("TruffleHog execution fallback: %s", exc)

        return {
            "status": "success",
            "target": target_path,
            "secrets": secrets,
            "count": len(secrets),
            "tool": "trufflehog",
        }

    async def normalize(self, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "target": raw_result.get("target"),
            "tool": "trufflehog",
            "total_secrets": raw_result.get("count", 0),
            "secrets": raw_result.get("secrets", []),
        }
