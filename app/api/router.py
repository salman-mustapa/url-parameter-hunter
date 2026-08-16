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
from app.models.models import Asset, AuditLog, Finding, Port, Scan, ScanEvent
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


@router.get("/domains/{domain}/history")
async def domain_history(domain: str, db: AsyncSession = Depends(get_db)):
    scans = (await db.execute(
        select(Scan).where(Scan.root_domain == domain).order_by(desc(Scan.created_at))
    )).scalars().all()
    return [
        {"id": s.id, "status": s.status, "profile": s.profile, "progress": s.progress or {},
         "created_at": s.created_at.isoformat() if s.created_at else None,
         "completed_at": s.completed_at.isoformat() if s.completed_at else None}
        for s in scans
    ]


@router.get("/diff")
async def diff_scans(current: str = Query(...), previous: str = Query(...), db: AsyncSession = Depends(get_db)):
    """Differential scan: NEW/CHANGED/REMOVED across two scans on same domain."""
    async def key_set(scan_id: str):
        rows = (await db.execute(
            select(Asset).where(Asset.scan_id == scan_id, Asset.asset_type.in_(["domain", "subdomain"]))
        )).scalars().all()
        return {r.hostname: r for r in rows if r.hostname}

    cur = await key_set(current)
    prev = await key_set(previous)
    added = sorted(set(cur) - set(prev))
    removed = sorted(set(prev) - set(cur))

    async def port_set(scan_id: str):
        ids = select(Asset.id).where(Asset.scan_id == scan_id)
        rows = (await db.execute(select(Port).where(Port.asset_id.in_(ids)))).scalars().all()
        return {(p.ip, p.port, p.protocol) for p in rows}

    pc, pp = await port_set(current), await port_set(previous)
    new_ports = sorted(f"{ip}:{port}/{proto}" for ip, port, proto in (pc - pp))

    async def finding_set(scan_id: str):
        rows = (await db.execute(select(Finding).where(Finding.scan_id == scan_id))).scalars().all()
        return {(f.finding_type, f.title) for f in rows}

    fc, fp = await finding_set(current), await finding_set(previous)
    new_findings = sorted(f"{ft}: {t}" for ft, t in (fc - fp))
    changed = [h for h in sorted(set(cur) & set(prev)) if (cur[h].ip or "") != (prev[h].ip or "")]

    return {
        "current": current, "previous": previous,
        "new_subdomains": added, "removed_subdomains": removed,
        "changed_ip": changed, "new_ports": new_ports, "new_findings": new_findings,
    }


@router.get("/scans/{scan_id}/events/{asset_id}/timeline")
async def asset_timeline(scan_id: str, asset_id: str, db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(
        select(ScanEvent).where(ScanEvent.scan_id == scan_id, ScanEvent.asset_id == asset_id)
        .order_by(ScanEvent.created_at.asc())
    )).scalars().all()
    return [
        {"event_type": e.event_type, "severity": e.severity, "message": e.message,
         "data": e.data or {}, "created_at": e.created_at.isoformat() if e.created_at else None}
        for e in rows
    ]


@router.get("/metrics")
async def metrics(db: AsyncSession = Depends(get_db)):
    total = (await db.execute(select(func.count()).select_from(Scan))).scalar() or 0
    queued = (await db.execute(select(func.count()).select_from(Scan).where(Scan.status == "queued"))).scalar() or 0
    running = (await db.execute(select(func.count()).select_from(Scan).where(Scan.status == "running"))).scalar() or 0
    completed = (await db.execute(select(func.count()).select_from(Scan).where(Scan.status == "completed"))).scalar() or 0
    failed = (await db.execute(select(func.count()).select_from(Scan).where(Scan.status == "partial_failure"))).scalar() or 0
    ended = (await db.execute(select(func.count()).select_from(Scan).where(Scan.status.in_(["stopped", "cancelled"])))).scalar() or 0
    domains = (await db.execute(select(func.count()).select_from(Asset).where(Asset.asset_type == "domain"))).scalar() or 0
    subdomains = (await db.execute(select(func.count()).select_from(Asset).where(Asset.asset_type == "subdomain"))).scalar() or 0
    ips = (await db.execute(select(func.count()).select_from(Asset).where(Asset.asset_type == "ip"))).scalar() or 0
    return {
        "scans": {"total": total, "queued": queued, "running": running, "completed": completed, "failed": failed, "stopped": ended},
        "assets": {"domains": domains, "subdomains": subdomains, "ips": ips},
        "queue_depth": queued,
    }


@router.get("/findings/severity")
async def findings_by_severity(scan_id: str = Query(...), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(
        select(Finding.severity, func.count()).where(Finding.scan_id == scan_id).group_by(Finding.severity)
    )).all()
    return {"severities": {sev: count for sev, count in rows}, "total": sum(c for _, c in rows)}


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