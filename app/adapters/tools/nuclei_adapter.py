"""Nuclei Vulnerability & Misconfiguration Tool Adapter (V11)."""

from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
from typing import Any, Dict, List, Optional, Set

from app.adapters.base.base_adapter import BaseAdapter
from app.core.config import settings
from app.core.subprocess_runner import run_bounded_subprocess

logger = logging.getLogger("adapter.nuclei")


class NucleiAdapter(BaseAdapter):
    """Adapter for Nuclei fast and customizable vulnerability scanner."""

    name: str = "nuclei_adapter"
    version: str = "11.0.0"
    capabilities: Set[str] = {"vulnerability_scanning", "misconfiguration_detection", "cve_audit", "template_clustering"}

    def __init__(self) -> None:
        self._binary_path: str | None = shutil.which("nuclei")

    async def healthcheck(self) -> bool:
        self._binary_path = shutil.which("nuclei")
        return self._binary_path is not None

    async def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        targets = task.get("targets") or []
        single_target = task.get("url") or task.get("target") or task.get("host")
        if single_target and single_target not in targets:
            targets.append(single_target)

        tags = task.get("tags") or getattr(settings, "nuclei_tags", "cve,misconfig,exposure,tech")
        severity = task.get("severity", "critical,high,medium,low,info")
        rate_limit = str(task.get("rate_limit") or getattr(settings, "nuclei_rate_limit", 50))
        concurrency = str(task.get("concurrency") or getattr(settings, "nuclei_concurrency", 25))
        timeout_sec = float(task.get("timeout") or getattr(settings, "nuclei_timeout_seconds", 30.0))

        if not targets:
            return {"status": "error", "error": "No target provided", "findings": [], "count": 0}

        findings: List[Dict[str, Any]] = []

        if self._binary_path:
            tmp_target_file: Optional[str] = None
            try:
                cmd = [
                    self._binary_path,
                    "-tags", tags,
                    "-s", severity,
                    "-silent",
                    "-jsonl",
                    "-timeout", "10",
                    "-rate-limit", rate_limit,
                    "-c", concurrency,
                ]

                if len(targets) > 1:
                    fd, tmp_target_file = tempfile.mkstemp(prefix="nuclei_targets_", suffix=".txt", text=True)
                    with os.fdopen(fd, "w", encoding="utf-8") as f:
                        for t in targets:
                            f.write(f"{t}\n")
                    cmd.extend(["-list", tmp_target_file])
                else:
                    cmd.extend(["-u", targets[0]])

                proc_result = await run_bounded_subprocess(cmd, timeout_seconds=max(timeout_sec, 45.0))
                if proc_result.timed_out:
                    return {"status": "timeout", "target": targets[0], "findings": [], "count": 0, "tool": "nuclei"}

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
                                "cvss_score": obj.get("info", {}).get("classification", {}).get("cvss-score"),
                                "extracted_results": obj.get("extracted-results", []),
                                "curl_command": obj.get("curl-command"),
                            })
                        except Exception:
                            continue
            except Exception as exc:
                logger.debug("Nuclei execution note: %s", exc)
            finally:
                if tmp_target_file and os.path.exists(tmp_target_file):
                    try:
                        os.remove(tmp_target_file)
                    except Exception:
                        pass

        return {
            "status": "success",
            "target": targets[0] if targets else "",
            "targets_scanned": len(targets),
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
