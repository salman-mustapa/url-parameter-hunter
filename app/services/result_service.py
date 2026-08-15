from sqlalchemy.ext.asyncio import AsyncSession
from app.models.models import ScanEvent
from datetime import datetime, timezone

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
