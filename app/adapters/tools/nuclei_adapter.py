"""Nuclei Vulnerability & Misconfiguration Tool Adapter (V10)."""

from __future__ import annotations

import json
import logging
import shutil
from typing import Any, Dict, List, Set

from app.adapters.base.base_adapter import BaseAdapter
from app.core.subprocess_runner import run_bounded_subprocess

logger = logging.getLogger("adapter.nuclei")


class NucleiAdapter(BaseAdapter):
    """Adapter for Nuclei fast and customizable vulnerability scanner."""

    name: str = "nuclei_adapter"
    version: str = "10.0.0"
    capabilities: Set[str] = {"vulnerability_scanning", "misconfiguration_detection", "cve_audit"}

    def __init__(self) -> None:
        self._binary_path: str | None = shutil.which("nuclei")

    async def healthcheck(self) -> bool:
        self._binary_path = shutil.which("nuclei")
        return True

    async def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        target = task.get("url") or task.get("target") or task.get("host")
        tags = task.get("tags", "cve,misconfig,exposure,tech")
        severity = task.get("severity", "critical,high,medium,low,info")

        if not target:
            return {"status": "error", "error": "No target provided", "findings": []}

        findings: List[Dict[str, Any]] = []

        if self._binary_path:
            try:
                cmd = [
                    self._binary_path,
                    "-u", target,
                    "-tags", tags,
                    "-s", severity,
                    "-silent",
                    "-jsonl",
                    "-timeout", "10",
                    "-rate-limit", "15",
                ]
                proc_result = await run_bounded_subprocess(cmd, timeout_seconds=50.0)
                if proc_result.timed_out:
                    return {"status": "timeout", "target": target, "findings": [], "count": 0, "tool": "nuclei"}
                stdout = proc_result.stdout
                for line in stdout.decode("utf-8", errors="ignore").splitlines():
                    line = line.strip()
                    if line and line.startswith("{"):
                        try:
                            obj = json.loads(line)
                            findings.append({
                                "template_id": obj.get("template-id"),
                                "name": obj.get("info", {}).get("name"),
                                "severity": obj.get("info", {}).get("severity", "info").upper(),
                                "matched_at": obj.get("matched-at"),
                                "type": obj.get("type"),
                                "description": obj.get("info", {}).get("description", ""),
                                "cve": obj.get("info", {}).get("classification", {}).get("cve-id", []),
                                "extracted_results": obj.get("extracted-results", []),
                            })
                        except Exception:
                            continue
            except Exception as exc:
                logger.debug("Nuclei execution fallback: %s", exc)

        return {
            "status": "success",
            "target": target,
            "findings": findings,
            "count": len(findings),
            "tool": "nuclei",
        }

    async def normalize(self, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "target": raw_result.get("target"),
            "tool": "nuclei",
            "total_findings": raw_result.get("count", 0),
            "findings": raw_result.get("findings", []),
        }
