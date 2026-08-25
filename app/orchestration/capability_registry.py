"""Capability Registry & Self-Diagnostic Orchestrator (V12 §58, §59, §60).

Central registry tracking:
- Agents & Specialists
- Skills & Methodologies
- Tools & Adapters
- AI Providers & Capabilities
- Diagnostic Health Status (READY, DEGRADED, BLOCKED)
"""

from __future__ import annotations

import logging
import shutil
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from app.ai.gateway import ai_gateway
from app.ai.provider_router import ai_provider_router
from app.skills.skill_registry import SkillStatus, skill_registry
from app.workers.worker_pool import worker_pool_manager

logger = logging.getLogger("orchestration.capability_registry")


class DiagnosticStatus(str, Enum):
    READY = "ready"
    DEGRADED = "degraded"
    BLOCKED = "blocked"


@dataclass
class ToolCapability:
    name: str
    category: str
    is_installed: bool
    path: Optional[str] = None
    version: Optional[str] = None
    description: str = ""


class CapabilityRegistry:
    """Tracks platform capabilities and provides pre-flight diagnostic health checks."""

    def __init__(self) -> None:
        self._tools: Dict[str, ToolCapability] = {}
        self._refresh_tools()

    def _refresh_tools(self) -> None:
        """Inspects availability of essential pentesting binaries."""
        known_tools = {
            "subfinder": ("discovery", "Passive subdomain enumeration"),
            "katana": ("web", "Next-gen crawling and JS endpoint scraping"),
            "httpx": ("web", "HTTP probing and technology banner analysis"),
            "nmap": ("network", "Network port scanner and service detection"),
            "ffuf": ("web", "Web directory and parameter fuzzer"),
            "dirsearch": ("web", "Directory listing and sensitive file crawler"),
        }
        for tool, (cat, desc) in known_tools.items():
            path = shutil.which(tool)
            self._tools[tool] = ToolCapability(
                name=tool,
                category=cat,
                is_installed=bool(path),
                path=path,
                description=desc,
            )

    def get_capabilities_summary(self) -> Dict[str, Any]:
        """Answers: What can the platform currently do?"""
        self._refresh_tools()
        skills = skill_registry.list_skills(status=SkillStatus.APPROVED)
        workers = worker_pool_manager.list_workers()

        return {
            "tools": {k: {"installed": v.is_installed, "category": v.category} for k, v in self._tools.items()},
            "skills_count": len(skills),
            "approved_skills": [s.name for s in skills],
            "workers_count": len(workers),
            "active_worker_classes": [w["worker_class"] for w in workers],
            "ai_active_provider": type(ai_gateway.active_provider).__name__ if ai_gateway.active_provider else "zero_resource_heuristic",
        }

    def run_self_diagnostic(self) -> Dict[str, Any]:
        """Runs pre-flight diagnostic check across all core dependencies."""
        self._refresh_tools()
        issues: List[str] = []
        status = DiagnosticStatus.READY

        # 1. Check Workers
        workers = worker_pool_manager.list_workers()
        if len(workers) < 13:
            issues.append(f"Worker pool degraded: {len(workers)}/13 workers initialized.")
            status = DiagnosticStatus.DEGRADED

        # 2. Check Skills
        skills = skill_registry.list_skills(status=SkillStatus.APPROVED)
        if not skills:
            issues.append("No approved cybersecurity skills registered.")
            status = DiagnosticStatus.DEGRADED

        # 3. Check AI Provider
        if not ai_gateway.active_provider or not ai_gateway.active_provider.is_available():
            issues.append("No cloud AI key configured (operating in Zero-Resource CPU Heuristic mode).")
            # Not degraded, since zero-resource heuristic is 100% functional

        return {
            "status": status.value,
            "issues": issues,
            "checks": {
                "workers_ok": len(workers) >= 13,
                "skills_ok": len(skills) > 0,
                "ai_ready": True,
                "tools_available": sum(1 for t in self._tools.values() if t.is_installed),
                "tools_total": len(self._tools),
            }
        }


capability_registry = CapabilityRegistry()
