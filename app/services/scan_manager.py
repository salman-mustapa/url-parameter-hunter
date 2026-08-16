from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import func, select

from app.core.config import settings
from app.core.db import AsyncSessionLocal
from app.core.events import event_bus
from app.core.rate_limit import RateLimiter
from app.core.scope import Scope, normalize_target
from app.models.models import Asset, Scan
from app.scanners import dns, http, port, security, subdomain, web
from app.services.results import result_service

logger = logging.getLogger("scan_mgr")


class ScanManager:
    def __init__(self) -> None:
        self._running: Dict[str, asyncio.Task] = {}
        self._pause_events: Dict[str, asyncio.Event] = {}
        self._stop_flags: Dict[str, bool] = {}

    # ---------- public control ----------
    async def create_scan(self, target: str, profile: str = "standard", include_subdomains: bool = True) -> dict:
        host, root_domain = normalize_target(target)
        if profile not in ("passive", "standard", "deep"):
            profile = "standard"

        options: Dict[str, Any] = {
            "port_scan": True,
            "web_discovery": True,
            "parameter_discovery": True,
            "security_checks": True,
            "include_subdomains": include_subdomains,
            "strict_scope": False,
            "max_assets": settings.max_assets_per_scan,
            "max_urls": settings.max_urls_per_scan,
            "max_runtime_seconds": settings.max_runtime_minutes * 60,
        }

        scan_id = f"scan_{int(time.time())}_{host.replace('.', '_')}"
        async with AsyncSessionLocal() as db:
            scan = Scan(id=scan_id, root_domain=root_domain, status="queued", profile=profile, options=options)
            db.add(scan)
            await db.commit()

        await event_bus.publish(result_service.make_event(
            scan_id, "scan.started", f"Scan queued for {root_domain}",
            target=root_domain, profile=profile, severity="info"))
        self._run(scan_id, root_domain, profile, options)
        return {"scan_id": scan_id, "status": "queued", "target": root_domain, "profile": profile}

    def _run(self, scan_id: str, root_domain: str, profile: str, options: Dict[str, Any]) -> None:
        if scan_id in self._running:
            return
        ev = asyncio.Event()
        ev.set()  # running by default; pause() clears it
        self._pause_events[scan_id] = ev
        self._stop_flags[scan_id] = False
        task = asyncio.create_task(self._pipeline(scan_id, root_domain, profile, options))
        self._running[scan_id] = task

    async def pause(self, scan_id: str) -> None:
        ev = self._pause_events.get(scan_id)
        if ev:
            ev.clear()
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan:
                scan.status = "paused"
                await db.commit()
        await event_bus.publish(result_service.make_event(
            scan_id, "scan.paused", "Scan paused", severity="warn"))

    async def resume(self, scan_id: str) -> None:
        ev = self._pause_events.get(scan_id)
        if ev:
            ev.set()
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan:
                scan.status = "running"
                scan.started_at = scan.started_at or datetime.now(timezone.utc)
                await db.commit()
        await event_bus.publish(result_service.make_event(
            scan_id, "scan.resumed", "Scan resumed", severity="info"))

    async def stop(self, scan_id: str) -> None:
        self._stop_flags[scan_id] = True
        task = self._running.get(scan_id)
        if task:
            task.cancel()
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan and scan.status not in ("completed", "stopped", "cancelled"):
                scan.status = "stopped"
                scan.completed_at = datetime.now(timezone.utc)
                await db.commit()
        await event_bus.publish(result_service.make_event(
            scan_id, "scan.stopped", "Scan stopped", severity="warn"))

    # ---------- pipeline ----------
    async def _pipeline(self, scan_id: str, root_domain: str, profile: str, options: Dict[str, Any]) -> None:
        scope = Scope(root_domain)
        limiter = RateLimiter(settings.rate_limit_rps)
        ctx = ScanContextPort(scan_id, scope, profile, options, limiter)

        start_time = time.time()
        started = False
        try:
            # mark running
            await self._set_status(scan_id, "running", started_at=True)
            await event_bus.publish(result_service.make_event(
                scan_id, "scan.running", f"Pipeline running for {root_domain}", severity="info"))

            # ---- Phase: Discovery (subdomains) ----
            async with AsyncSessionLocal() as db:
                await self._checkpoint(ctx, db, root_domain, start_time)
                await subdomain.run(ctx, db, root_domain)

            # ---- Phase: DNS resolution for all assets ----
            async with AsyncSessionLocal() as db:
                await self._checkpoint(ctx, db, root_domain, start_time)
                await dns.run(ctx, db, root_domain)

            # ---- Phase: Port scan (resolved assets) ----
            if options.get("port_scan", True) and profile != "passive":
                async with AsyncSessionLocal() as db:
                    await self._checkpoint(ctx, db, root_domain, start_time)
                    await port.run(ctx, db, root_domain)

            # ---- Phase: HTTP probe + tech detection ----
            async with AsyncSessionLocal() as db:
                await self._checkpoint(ctx, db, root_domain, start_time)
                await http.run(ctx, db, root_domain)

            # ---- Phase: URL/endpoint discovery + params ----
            if options.get("web_discovery", True) and profile != "passive":
                async with AsyncSessionLocal() as db:
                    await self._checkpoint(ctx, db, root_domain, start_time)
                    await web.run(ctx, db, root_domain)

            # ---- Phase: Security analysis ----
            if options.get("security_checks", True) and profile != "passive":
                async with AsyncSessionLocal() as db:
                    await self._checkpoint(ctx, db, root_domain, start_time)
                    await security.run(ctx, db, root_domain)

            # ---- complete ----
            await self._complete(scan_id, root_domain)
        except asyncio.CancelledError:
            if not self._stop_flags.get(scan_id):
                raise
            await self._finish_status(scan_id, "stopped")
            await event_bus.publish(result_service.make_event(
                scan_id, "scan.stopped", "Scan stopped by user", severity="warn"))
        except Exception as exc:
            logger.exception("pipeline failed for %s", scan_id)
            await self._finish_status(scan_id, "partial_failure")
            await event_bus.publish(result_service.make_event(
                scan_id, "scan.failed", f"Scan failed: {exc}", severity="error"))
        finally:
            self._running.pop(scan_id, None)
            self._pause_events.pop(scan_id, None)
            self._stop_flags.pop(scan_id, None)

    async def _checkpoint(self, ctx: Any, db, root_domain: str, start_time: float) -> None:
        # pause handling
        pause_ev = self._pause_events.get(ctx.scan_id)
        if pause_ev and not pause_ev.is_set():
            while not pause_ev.is_set():
                await asyncio.sleep(0.5)
        # runtime limit
        if time.time() - start_time > settings.max_runtime_minutes * 60:
            raise RuntimeError("Max runtime exceeded")
        # asset limit
        count = (await db.execute(
            select(func.count()).select_from(Asset).where(Asset.scan_id == ctx.scan_id)
        )).scalar() or 0
        if count >= settings.max_assets_per_scan:
            raise RuntimeError("Max assets limit reached")

    async def _set_status(self, scan_id: str, status: str, started_at: bool = False) -> None:
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan:
                scan.status = status
                if started_at:
                    scan.started_at = scan.started_at or datetime.now(timezone.utc)
                await db.commit()

    async def _finish_status(self, scan_id: str, status: str) -> None:
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan:
                scan.status = status
                scan.completed_at = datetime.now(timezone.utc)
                await db.commit()

    async def _complete(self, scan_id: str, root_domain: str) -> None:
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if not scan:
                return
            assets = (await db.execute(
                select(func.count()).select_from(Asset).where(Asset.scan_id == scan_id)
            )).scalar() or 0
            from app.models.models import Finding
            findings = (await db.execute(
                select(func.count()).select_from(Finding).where(Finding.scan_id == scan_id)
            )).scalar() or 0
            scan.status = "completed"
            scan.completed_at = datetime.now(timezone.utc)
            scan.progress = {"assets": assets, "findings": findings}
            await db.commit()
        await event_bus.publish(result_service.make_event(
            scan_id, "scan.completed", f"Scan completed for {root_domain}",
            assets=assets, findings=findings, severity="success"))


class ScanContextPort:
    """Adapter so scanner modules receive the canonical ScanContext."""

    def __init__(self, scan_id: str, scope: Scope, profile: str, options: Dict[str, Any], limiter: RateLimiter):
        self.scan_id = scan_id
        self.scope = scope
        self.profile = profile
        self.options = options
        self.rate_limiter = limiter

    async def emit(self, event_type: str, message: str, **data) -> None:
        ev = result_service.make_event(self.scan_id, event_type, message, **data)
        await event_bus.publish(ev)


scan_manager = ScanManager()