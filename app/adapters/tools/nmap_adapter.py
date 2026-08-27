"""Nmap Network Recon Adapter (V10)."""

from __future__ import annotations

import logging
import re
import shutil
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Set

from app.adapters.base.base_adapter import BaseAdapter
from app.core.config import settings
from app.core.subprocess_runner import run_bounded_subprocess

logger = logging.getLogger("adapter.nmap")

_SAFE_TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _normalize_target(value: Any) -> str | None:
    target = str(value or "").strip().rstrip(".")
    if not target or target.startswith("-") or not _SAFE_TARGET_RE.fullmatch(target):
        return None
    return target


def _normalize_ports(value: Any, *, max_items: int | None = None) -> str | None:
    normalized: List[str] = []
    seen: Set[str] = set()
    raw_parts: List[str] = []
    if isinstance(value, (list, tuple, set)):
        raw_parts = [str(x).strip() for x in value if str(x).strip()]
    else:
        raw_parts = [p.strip() for p in str(value or "").split(",") if p.strip()]

    for part in raw_parts:
        if not part:
            continue
        if part.isdigit():
            port = int(part)
            if not 1 <= port <= 65535:
                return None
            canonical = str(port)
        else:
            match = re.fullmatch(r"(\d{1,5})-(\d{1,5})", part)
            if not match:
                return None
            start, end = (int(match.group(1)), int(match.group(2)))
            if not (1 <= start <= end <= 65535) or end - start > 4096:
                return None
            canonical = f"{start}-{end}"
        if canonical not in seen:
            seen.add(canonical)
            normalized.append(canonical)
        if max_items is not None and len(normalized) >= max_items:
            break
    return ",".join(normalized) if normalized else None


class NmapAdapter(BaseAdapter):
    """Adapter for Nmap port scanner and service detection."""

    name: str = "nmap_adapter"
    version: str = "10.0.0"
    capabilities: Set[str] = {"port_scanning", "service_detection", "os_fingerprinting"}

    def __init__(self) -> None:
        self._binary_path: str | None = shutil.which("nmap")

    async def healthcheck(self) -> bool:
        self._binary_path = shutil.which("nmap")
        return bool(self._binary_path)

    async def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        target = _normalize_target(task.get("host") or task.get("target"))
        ports = _normalize_ports(
            task.get("ports", "80,443,8080,8443,3000,5000,8000,9000")
        )

        if not target:
            return {"status": "error", "error": "Invalid target host", "open_ports": []}
        if not ports:
            return {"status": "error", "error": "Invalid port selection", "open_ports": []}
        if not self._binary_path:
            return {"status": "unavailable", "error": "Nmap binary not found", "open_ports": []}

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
                proc_result = await run_bounded_subprocess(cmd, timeout_seconds=35.0)
                if proc_result.timed_out:
                    return {
                        "status": "timeout",
                        "target": target,
                        "error": "Nmap service detection exceeded 35 seconds",
                        "open_ports": [],
                    }
                if proc_result.returncode != 0:
                    return {
                        "status": "error",
                        "target": target,
                        "error": proc_result.stderr.decode("utf-8", errors="ignore")[:1000],
                        "open_ports": [],
                    }

                root = ET.fromstring(proc_result.stdout.decode("utf-8", errors="ignore"))
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
                logger.debug("Nmap execution failed: %s", exc)
                return {
                    "status": "error",
                    "target": target,
                    "error": str(exc),
                    "open_ports": [],
                }

        return {
            "status": "success",
            "target": target,
            "open_ports": open_ports,
            "count": len(open_ports),
            "tool": "nmap",
        }

    async def execute_vuln_scan(self, host: str, ports: str) -> Dict[str, Any]:
        """Run non-destructive NSE vulnerability checks with hard resource limits."""
        target = _normalize_target(host)
        normalized_ports = _normalize_ports(ports, max_items=settings.nmap_vuln_max_ports)
        findings: List[Dict[str, Any]] = []
        if not target:
            return {"status": "error", "error": "Invalid target host", "findings": []}
        if not normalized_ports:
            return {"status": "error", "error": "Invalid port selection", "findings": []}
        if not self._binary_path:
            self._binary_path = shutil.which("nmap")
        if not self._binary_path:
            return {"status": "unavailable", "error": "Nmap binary not found", "findings": []}

        try:
            cmd = [
                self._binary_path,
                "-p", normalized_ports,
                "-sV",
                "--script", "vuln and safe",
                "--script-timeout", f"{max(5, settings.nmap_vuln_script_timeout_seconds)}s",
                "--host-timeout", f"{max(30, int(settings.nmap_vuln_timeout_seconds))}s",
                "-oX", "-",
                target,
            ]
            timeout_seconds = max(30.0, settings.nmap_vuln_timeout_seconds + 10.0)
            proc_result = await run_bounded_subprocess(cmd, timeout_seconds=timeout_seconds)
            if proc_result.timed_out:
                return {
                    "status": "timeout",
                    "target": target,
                    "error": f"Nmap NSE scan exceeded {timeout_seconds:.0f} seconds",
                    "findings": [],
                    "count": 0,
                    "tool": "nmap_vuln",
                }
            if proc_result.returncode != 0:
                return {
                    "status": "error",
                    "target": target,
                    "error": proc_result.stderr.decode("utf-8", errors="ignore")[:1000],
                    "findings": [],
                    "count": 0,
                    "tool": "nmap_vuln",
                }

            root = ET.fromstring(proc_result.stdout.decode("utf-8", errors="ignore"))
            for port_elem in root.findall(".//port"):
                p_id = int(port_elem.get("portid", 0))
                proto = port_elem.get("protocol", "tcp")
                svc_elem = port_elem.find("service")
                svc_name = svc_elem.get("name", "unknown") if svc_elem is not None else "unknown"

                for script_elem in port_elem.findall("script"):
                    script_id = script_elem.get("id", "")
                    output = script_elem.get("output", "")

                    output_lower = output.lower()
                    negative = bool(re.search(r"\bnot vulnerable\b|\bstate:\s*(?:safe|not vulnerable)\b", output_lower))
                    positive = bool(re.search(r"\bstate:\s*vulnerable\b|\bvulnerable:\s", output_lower))
                    if positive and not negative:
                        severity = "HIGH"
                        if re.search(r"remote code execution|\brce\b", output_lower):
                            severity = "CRITICAL"
                        elif re.search(r"information disclosure|denial of service|\bdos\b", output_lower):
                            severity = "MEDIUM"
                        cves = sorted({cve.upper() for cve in _CVE_RE.findall(output)})
                        findings.append({
                            "port": p_id,
                            "protocol": proto,
                            "service": svc_name,
                            "script_id": script_id,
                            "output": output[:16000],
                            "severity": severity,
                            "cves": cves,
                            "state": "VULNERABLE",
                        })
        except Exception as exc:
            logger.debug("Nmap vuln scan execution failed: %s", exc)
            return {
                "status": "error",
                "target": target,
                "error": str(exc),
                "findings": [],
                "count": 0,
                "tool": "nmap_vuln",
            }

        return {
            "status": "success",
            "target": target,
            "ports": normalized_ports,
            "findings": findings,
            "count": len(findings),
            "tool": "nmap_vuln",
        }


    async def normalize(self, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "target": raw_result.get("target"),
            "tool": "nmap",
            "ports": raw_result.get("open_ports", []),
        }
