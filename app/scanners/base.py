from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.events import event_bus
from app.core.rate_limit import RateLimiter
from app.core.scope import Scope
from app.models.models import Asset
from app.services.results import result_service

logger = logging.getLogger("scanner")


class ScanContext:
    def __init__(self, scan_id: str, scope: Scope, profile: str, options: Dict[str, Any], rate_limiter: RateLimiter):
        self.scan_id = scan_id
        self.scope = scope
        self.profile = profile
        self.options = options
        self.rate_limiter = rate_limiter
        self._parent_cache: dict[str, str] = {}
        self.coverage_failures: list[dict[str, str]] = []

    def record_coverage_gap(self, phase: str, error: str) -> None:
        item = {"phase": phase, "error": str(error)[:300]}
        if item not in self.coverage_failures and len(self.coverage_failures) < 200:
            self.coverage_failures.append(item)

    def module_allowed(self, module_name: str) -> bool:
        configured = {str(item).lower() for item in self.options.get("allowed_modules", [])}
        name = str(module_name).lower()
        return (not configured or "*" in configured or name in configured) and self.scope.module_allowed(name)

    def action_allowed(self, action_name: str) -> bool:
        name = str(action_name).lower().replace("-", "_")
        prohibited = {
            str(item).lower().replace("-", "_")
            for item in self.options.get("prohibited_actions", [])
        }
        if any(item == name or item in name or name in item for item in prohibited):
            return False
        configured = {
            str(item).lower().replace("-", "_")
            for item in self.options.get("allowed_actions", [])
        }
        if not configured or "*" in configured:
            return True
        if name in configured:
            return True
        validation_tools = {
            "nuclei", "dalfox", "sqli", "xss", "idor", "ssrf",
            "sqli_validator", "xss_validator", "idor_validator", "ssrf_validator",
            "path_traversal_validator", "open_redirect_validator", "sensitive_files_scanner",
        }
        return "validation" in configured and name in validation_tools

    async def get_parent_asset_id(self, db: AsyncSession, hostname: str, scan_id: str) -> Optional[str]:
        if hostname in self._parent_cache:
            return self._parent_cache[hostname]
        from sqlalchemy import select

        from app.models.models import Asset
        existing = (await db.execute(
            select(Asset).where(Asset.scan_id == scan_id, Asset.hostname == hostname)
        )).scalar_one_or_none()
        if existing:
            self._parent_cache[hostname] = existing.id
            return existing.id
        return None

    async def emit(self, event_type: str, message: str, **data) -> None:
        ev = result_service.make_event(self.scan_id, event_type, message, **data)
        await event_bus.publish(ev)
        # Feed discovery events into Adaptive Orchestrator for real-time opportunity escalation
        try:
            from app.orchestration.adaptive_orchestrator import adaptive_orchestrator
            event_payload = {"scan_id": self.scan_id, "message": message, **data}
            # Ingest with backpressure; do not leave detached event tasks running
            # after their scan has completed or been cancelled.
            await adaptive_orchestrator.ingest_event(event_type, event_payload)
        except Exception as exc:
            logger.debug("Adaptive orchestrator dispatch failed for %s: %s", event_type, exc)


class Scanner(Protocol):
    name: str

    async def run(self, ctx: ScanContext, db: AsyncSession, root_domain: str) -> None: ...
