from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.services.database import AsyncSessionLocal
from app.models.models import Finding

router = APIRouter(prefix="/api/findings", tags=["findings"])

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

@router.get("")
async def list_findings(scan_id: str = Query(...), db: AsyncSession = Depends(get_db)):
    stmt = select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.first_seen.desc())
    rows = (await db.execute(stmt)).scalars().all()
    return [{"id": r.id, "severity": r.severity, "title": r.title, "status": r.status, "confidence": r.confidence} for r in rows]
