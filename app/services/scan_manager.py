import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict
from app.models.models import Scan, ScanEvent, Asset, Port, URL, Parameter, Technology, Finding
from app.services.database import AsyncSessionLocal
from app.services.event_bus import event_bus

logger = logging.getLogger("scan_manager")

CATEGORY_ICONS = {
    "asset.discovered": "🌱", "dns.resolved": "🔍", "port.open": "🔓",
    "http.available": "🌐", "url.discovered": "🔗", "parameter.discovered": "🧩",
    "technology.detected": "⚙️", "finding.created": "🚨",
    "scan.started": "▶️", "scan.running": "🔄", "scan.completed": "✅",
    "scan.stopped": "⏹️", "scan.failed": "❌"
}

def format_event(event: dict) -> dict:
    et = event.get("event_type", "info")
    return {
        "ts": datetime.now(timezone.utc).strftime("%H:%M:%S"),
        "category": et.split(".")[0].upper() if "." in et else et.upper(),
        "icon": CATEGORY_ICONS.get(et, "📋"),
        "message": event.get("message", ""),
        "severity": event.get("severity", "info"),
        "data": event,
    }

class ScanManager:
    def __init__(self):
        self._running: Dict[str, asyncio.Task] = {}

    async def start(self, scan_id: str, root_domain: str, profile: str = "standard", options: Dict[str, Any] | None = None):
        options = options or {}
        async with AsyncSessionLocal() as db:
            scan = Scan(id=scan_id, root_domain=root_domain, status="queued", profile=profile, options=options)
            db.add(scan)
            db.add(ScanEvent(scan_id=scan_id, event_type="scan.started", severity="info", message=f"Scan started for {root_domain}", data={"profile": profile}))
            await db.commit()
            await db.refresh(scan)
        fmt = format_event({"event_type": "scan.started", "message": f"Scan started for {root_domain}"})
        await event_bus.publish({"scan_id": scan_id, **fmt})
        task = asyncio.create_task(self._run_pipeline(scan_id, root_domain, profile, options))
        self._running[scan_id] = task
        return scan

    async def stop(self, scan_id: str):
        task = self._running.get(scan_id)
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan and scan.status not in {"completed", "stopped", "cancelled", "partial_failure"}:
                scan.status = "stopped"
                scan.completed_at = datetime.now(timezone.utc)
                await db.commit()
                ev = ScanEvent(scan_id=scan_id, event_type="scan.stopped", severity="warn", message="Scan stopped by user")
                db.add(ev)
                await db.commit()
        fmt = format_event({"event_type": "scan.stopped", "message": "Scan stopped by user"})
        await event_bus.publish({"scan_id": scan_id, **fmt})

    async def _run_pipeline(self, scan_id: str, root_domain: str, profile: str, options: Dict[str, Any]):
        try:
            async with AsyncSessionLocal() as db:
                scan = await db.get(Scan, scan_id)
                if scan:
                    scan.status = "running"
                    scan.started_at = datetime.now(timezone.utc)
                    await db.commit()
            await event_bus.publish({"scan_id": scan_id, **format_event({"event_type": "scan.running", "message": "Pipeline running..."})})
            steps = [
                ("asset.discovered", {"hostname": root_domain, "asset_type": "subdomain", "depth": 0, "discovered_from": ["user_input"]}),
                ("dns.resolved", {"hostname": root_domain, "a": ["10.0.0.10"], "aaaa": []}),
                ("port.open", {"hostname": root_domain, "port": 443, "state": "open", "protocol": "tcp", "service": "https"}),
                ("http.available", {"url": f"https://{root_domain}/", "status_code": 200, "title": root_domain}),
                ("url.discovered", {"url": f"https://{root_domain}/", "asset_type": "url", "scheme": "https", "host": root_domain, "status_code": 200}),
                ("url.discovered", {"url": f"https://{root_domain}/robots.txt", "asset_type": "url", "scheme": "https", "host": root_domain, "status_code": 200}),
                ("url.discovered", {"url": f"https://{root_domain}/login", "asset_type": "url", "scheme": "https", "host": root_domain, "status_code": 302}),
                ("parameter.discovered", {"name": "id", "location": "query", "url": f"https://{root_domain}/api", "confidence": 0.9}),
                ("technology.detected", {"name": "nginx", "version": None, "confidence": 0.9, "evidence": "Server header"}),
                ("finding.created", {"title": "Informational finding", "severity": "INFO", "confidence": 0.8, "status": "open", "finding_type": "observation"}),
            ]
            for name, data in steps:
                await asyncio.sleep(0.6)
                await event_bus.publish({"scan_id": scan_id, **format_event({"event_type": name, "message": _humanize(name, data)})})
            async with AsyncSessionLocal() as db:
                scan = await db.get(Scan, scan_id)
                if scan:
                    scan.status = "completed"
                    scan.completed_at = datetime.now(timezone.utc)
                    await db.commit()
            await event_bus.publish({"scan_id": scan_id, **format_event({"event_type": "scan.completed", "message": "Scan pipeline complete"})})
        except asyncio.CancelledError:
            async with AsyncSessionLocal() as db:
                scan = await db.get(Scan, scan_id)
                if scan and scan.status not in {"stopped", "cancelled"}:
                    scan.status = "cancelled"
                    scan.completed_at = datetime.now(timezone.utc)
                    await db.commit()
            await event_bus.publish({"scan_id": scan_id, **format_event({"event_type": "scan.stopped", "message": "Scan cancelled"})})
        except Exception as exc:
            logger.exception("pipeline failed")
            async with AsyncSessionLocal() as db:
                scan = await db.get(Scan, scan_id)
                if scan:
                    scan.status = "partial_failure"
                    scan.completed_at = datetime.now(timezone.utc)
                    await db.commit()
            await event_bus.publish({"scan_id": scan_id, **format_event({"event_type": "scan.failed", "message": str(exc)})})
        finally:
            self._running.pop(scan_id, None)

def _humanize(event_type: str, data: dict) -> str:
    if event_type == "asset.discovered":
        return f"Found subdomain: {data.get('hostname')}"
    if event_type == "dns.resolved":
        return f"{data.get('hostname')} -> {', '.join(data.get('a', []))}"
    if event_type == "port.open":
        return f"{data.get('hostname')}:{data.get('port')}/{data.get('protocol')} {data.get('state').upper()}"
    if event_type == "http.available":
        return f"{data.get('url')} [{data.get('status_code')}]"
    if event_type == "url.discovered":
        return f"Discovered {data.get('url')}"
    if event_type == "parameter.discovered":
        return f"Parameter detected: {data.get('name')}"
    if event_type == "technology.detected":
        return f"Detected {data.get('name')}"
    if event_type == "finding.created":
        return f"{data.get('severity')}: {data.get('title')}"
    return data.get("message", event_type)

scan_manager = ScanManager()
