from __future__ import annotations

import asyncio
import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import AsyncSessionLocal, get_db
from app.core.events import event_bus
from app.models.models import Asset, AuditLog, Finding, Scan, ScanEvent
from app.services.assets import asset_detail, asset_tree
from app.services.results import result_service
from app.services.scan_manager import scan_manager

router = APIRouter(prefix="/api", tags=["api"])


@router.post("/scans")
async def create_scan(target: str = Query(...), profile: str = Query("standard"), include_subdomains: bool = Query(True)):
    try:
        return await scan_manager.create_scan(target, profile, include_subdomains)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/scans")
async def list_scans(db: AsyncSession = Depends(get_db)):
    scans = (await db.execute(select(Scan).order_by(desc(Scan.created_at)))).scalars().all()
    return [
        {
            "id": s.id, "root_domain": s.root_domain, "status": s.status, "profile": s.profile,
            "progress": s.progress or {},
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        }
        for s in scans
    ]


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "id": scan.id, "root_domain": scan.root_domain, "status": scan.status, "profile": scan.profile,
        "options": scan.options or {}, "progress": scan.progress or {},
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
    }


@router.post("/scans/{scan_id}/pause")
async def pause_scan(scan_id: str):
    await scan_manager.pause(scan_id)
    return {"scan_id": scan_id, "action": "pause", "status": "paused"}


@router.post("/scans/{scan_id}/resume")
async def resume_scan(scan_id: str):
    await scan_manager.resume(scan_id)
    return {"scan_id": scan_id, "action": "resume", "status": "resumed"}


@router.post("/scans/{scan_id}/stop")
async def stop_scan(scan_id: str):
    await scan_manager.stop(scan_id)
    return {"scan_id": scan_id, "action": "stop", "status": "stopped"}


@router.get("/scans/{scan_id}/events")
async def scan_events(scan_id: str):
    async def gen():
        queue: asyncio.Queue = asyncio.Queue()

        async with AsyncSessionLocal() as db:
            rows = (await db.execute(
                select(ScanEvent).where(ScanEvent.scan_id == scan_id).order_by(ScanEvent.created_at.asc())
            )).scalars().all()
            for ev in rows:
                await queue.put(json.dumps({
                    "scan_id": scan_id, "event_type": ev.event_type,
                    "category": ev.event_type.split(".")[0].upper() if "." in ev.event_type else ev.event_type.upper(),
                    "severity": ev.severity, "message": ev.message, "data": ev.data or {},
                    "created_at": ev.created_at.isoformat() if ev.created_at else None,
                }, default=str))

        async def handler(ev: dict):
            if ev.get("scan_id") == scan_id:
                await queue.put(json.dumps(ev, default=str))

        event_bus.subscribe("*", handler)
        try:
            while True:
                item = await queue.get()
                yield f"data: {item}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            event_bus.unsubscribe(handler)

    return StreamingResponse(gen(), media_type="text/event-stream")


@router.get("/assets/tree")
async def tree(scan_id: str = Query(...), db: AsyncSession = Depends(get_db)):
    return await asset_tree(db, scan_id)


@router.get("/assets/{asset_id}")
async def detail(asset_id: str, db: AsyncSession = Depends(get_db)):
    return await asset_detail(db, asset_id)


@router.get("/findings")
async def list_findings(scan_id: str = Query(...), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(
        select(Finding).where(Finding.scan_id == scan_id).order_by(desc(Finding.first_seen))
    )).scalars().all()
    return [
        {
            "id": f.id, "scan_id": f.scan_id, "asset_id": f.asset_id, "finding_type": f.finding_type,
            "title": f.title, "severity": f.severity, "confidence": f.confidence,
            "description": f.description, "evidence": f.evidence or {}, "status": f.status,
            "first_seen": f.first_seen.isoformat() if f.first_seen else None,
            "last_seen": f.last_seen.isoformat() if f.last_seen else None,
        }
        for f in rows
    ]


@router.patch("/findings/{finding_id}")
async def update_finding(finding_id: str, status: str = Query(...), db: AsyncSession = Depends(get_db)):
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding.status = status
    await db.commit()
    await event_bus.publish(result_service.make_event(
        finding.scan_id, "finding.updated", f"Finding status → {status}",
        finding_id=finding.id, status=status))
    return {"id": finding.id, "status": finding.status}


@router.get("/domains")
async def list_domains(db: AsyncSession = Depends(get_db)):
    scans = (await db.execute(select(Scan).order_by(desc(Scan.created_at)))).scalars().all()
    from collections import defaultdict
    by_domain = defaultdict(lambda: {"root_domain": "", "scan_count": 0, "last_scan": None})
    for s in scans:
        d = by_domain[s.root_domain]
        d["root_domain"] = s.root_domain
        d["scan_count"] += 1
        d["last_scan"] = (s.completed_at or s.created_at).isoformat() if (s.completed_at or s.created_at) else None
    return list(by_domain.values())


@router.get("/scan-stats")
async def scan_stats(db: AsyncSession = Depends(get_db)):
    total = (await db.execute(select(func.count()).select_from(Scan))).scalar() or 0
    running = (await db.execute(select(func.count()).select_from(Scan).where(Scan.status == "running"))).scalar() or 0
    assets_total = (await db.execute(select(func.count()).select_from(Asset))).scalar() or 0
    findings_total = (await db.execute(select(func.count()).select_from(Finding))).scalar() or 0
    return {"total_scans": total, "running": running, "assets": assets_total, "findings": findings_total}


@router.get("/audit")
async def list_audit(scan_id: Optional[str] = Query(None), db: AsyncSession = Depends(get_db)):
    stmt = select(AuditLog).order_by(desc(AuditLog.created_at)).limit(200)
    if scan_id:
        stmt = stmt.where(AuditLog.scan_id == scan_id)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {"id": a.id, "scan_id": a.scan_id, "actor": a.actor, "action": a.action,
         "target": a.target, "details": a.details or {}, "created_at": a.created_at.isoformat() if a.created_at else None}
        for a in rows
    ]