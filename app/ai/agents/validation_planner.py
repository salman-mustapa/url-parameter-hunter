"""Validation Planner AI Agent & Dynamic Test Plan Engine (V8 §10, §24).

Responsibilities:
- Selects relevant tests tailored specifically to discovered technology stack
- Identifies prerequisites (e.g. crawler output before parameter mining)
- Builds optimized test sequence
- Prunes irrelevant modules:
  - No SSH tests without SSH
  - No RDP tests without RDP
  - No database tests without DB exposure
  - No WordPress tests without WordPress
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set

from app.orchestration.test_plan import TEST_MODULES, TestModule

logger = logging.getLogger("ai.agents.validation_planner")


class ValidationPlannerAgent:
    """Specialized AI agent for dynamic, technology-aware test planning (V8 §10, §24)."""

    @classmethod
    async def build_tailored_plan(
        cls,
        target: str,
        detected_technologies: List[str],
        open_services: List[str],
        has_web: bool = True,
        profile: str = "standard",
    ) -> Dict[str, Any]:
        """Constructs an efficient, pruned test sequence based strictly on active services."""
        tech_set = {t.lower() for t in detected_technologies}
        service_set = {s.lower() for s in open_services}

        selected_modules: List[Dict[str, Any]] = []
        pruned_reasons: List[Dict[str, str]] = []

        for mod in TEST_MODULES:
            # 1. Check technology constraint
            if mod.technologies:
                if not any(req_tech in tech_set or req_tech in service_set for req_tech in mod.technologies):
                    pruned_reasons.append({
                        "module": mod.id,
                        "reason": f"Required technologies {mod.technologies} not detected.",
                    })
                    continue

            # 2. Check web constraint
            if not has_web and "web" in mod.asset_types:
                pruned_reasons.append({
                    "module": mod.id,
                    "reason": "Target has no HTTP/HTTPS web exposure.",
                })
                continue

            selected_modules.append({
                "module_id": mod.id,
                "name": mod.name,
                "category": mod.category,
                "risk_level": mod.risk_level,
                "priority": mod.priority,
                "dependencies": mod.dependencies,
            })

        # Sort modules by priority
        selected_modules.sort(key=lambda m: m["priority"])

        logger.info("ValidationPlanner: selected %d modules, pruned %d irrelevant modules for %s", len(selected_modules), len(pruned_reasons), target)

        return {
            "agent": "validation_planner_agent",
            "target": target,
            "profile": profile,
            "total_modules_selected": len(selected_modules),
            "execution_sequence": selected_modules,
            "pruned_modules_count": len(pruned_reasons),
            "pruned_summary": pruned_reasons[:10],
        }
