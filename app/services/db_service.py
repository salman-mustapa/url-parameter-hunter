from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.models.models import Scan, ScanEvent, Asset
from typing import List

async def create_scan(db: AsyncSession, root_domain: str, profile: str, options: dict) -> Scan:
    scan = Scan(root_domain=root_domain, status="queued", profile=profile, options=options)
    db.add(scan)
    await db.flush()
    await db.refresh(scan)
    ev = ScanEvent(scan_id=scan.id, event_type="scan.started", severity="info", message=f"Scan queued for {root_domain}", data={"profile": profile, "options": options})
    db.add(ev)
    await db.commit()
    return scan

async def get_scan(db: AsyncSession, scan_id: str) -> Scan | None:
    return await db.get(Scan, scan_id)

async def list_scans(db: AsyncSession) -> List[Scan]:
    stmt = select(Scan).order_by(Scan.created_at.desc())
    return (await db.execute(stmt)).scalars().all()

async def update_scan_status(db: AsyncSession, scan_id: str, status: str):
    scan = await db.get(Scan, scan_id)
    if scan:
        scan.status = status
        if status in {"completed", "partial_failure", "stopped", "cancelled"}:
            from datetime import datetime
            scan.completed_at = datetime.utcnow()
        await db.commit()

async def append_event(db: AsyncSession, scan_id: str, event: dict):
    ev = ScanEvent(
        scan_id=scan_id,
        asset_id=event.get("asset_id"),
        event_type=event.get("event_type"),
        severity=event.get("severity", "info"),
        message=event.get("message", ""),
        data=event,
    )
    db.add(ev)
    await db.commit()
