from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingHTTPResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import json, asyncio
from app.services.database import AsyncSessionLocal
from app.models.models import Scan, ScanEvent
from app.services.scan_manager import scan_manager
from app.services.event_bus import event_bus
from app.core.config import settings

router = APIRouter(prefix="/api/scans", tags=["scans"])

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

@router.post("")
async def create_scan(target: str = Query(...), profile: str = Query("standard"), include_subdomains: bool = Query(True)):
    scan_id = f"scan_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    options = {"port_scan": True, "web_discovery": True, "parameter_discovery": True, "security_checks": True, "include_subdomains": include_subdomains}
    scan = await scan_manager.start(scan_id, target, profile=profile, options=options)
    return {"scan_id": scan.id, "status": scan.status, "target": scan.root_domain, "profile": scan.profile}

@router.get("")
async def list_scans(db: AsyncSession = Depends(get_db)):
    scans = (await db.execute(select(Scan).order_by(Scan.created_at.desc()))).scalars().all()
    return [{"id": s.id, "root_domain": s.root_domain, "status": s.status, "profile": s.profile, "created_at": s.created_at.isoformat() if s.created_at else None, "completed_at": s.completed_at.isoformat() if s.completed_at else None} for s in scans]

@router.get("/{scan_id}")
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if not scan:
        return {"error": "not found"}
    return {"id": scan.id, "root_domain": scan.root_domain, "status": scan.status, "profile": scan.profile, "options": scan.options, "progress": scan.progress or {}, "created_at": scan.created_at.isoformat() if scan.created_at else None}

@router.post("/{scan_id}/pause")
async def pause_scan(scan_id: str):
    return {"scan_id": scan_id, "action": "pause", "status": "not_implemented"}

@router.post("/{scan_id}/resume")
async def resume_scan(scan_id: str):
    return {"scan_id": scan_id, "action": "resume", "status": "not_implemented"}

@router.post("/{scan_id}/stop")
async def stop_scan(scan_id: str):
    await scan_manager.stop(scan_id)
    return {"scan_id": scan_id, "action": "stop", "status": "accepted"}

@router.get("/{scan_id}/events")
async def scan_events(scan_id: str):
    async def gen():
        queue: asyncio.Queue = asyncio.Queue()
        async with AsyncSessionLocal() as db:
            stmt = select(ScanEvent).where(ScanEvent.scan_id == scan_id).order_by(ScanEvent.created_at.asc())
            rows = (await db.execute(stmt)).scalars().all()
            for ev in rows:
                await queue.put(json.dumps({"scan_id": scan_id, "event_type": ev.event_type, "severity": ev.severity, "message": ev.message, "data": ev.data, "created_at": ev.created_at.isoformat() if ev.created_at else None}))
        async def handler(ev: dict):
            if ev.get("scan_id") == scan_id:
                await queue.put(json.dumps(ev))
        event_bus.subscribe("*", handler)
        try:
            while True:
                item = await queue.get()
                yield f"data: {item}\n\n"
        except asyncio.CancelledError:
            pass
    return StreamingHTTPResponse(gen(), media_type="text/event-stream")
