from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.services.database import AsyncSessionLocal
from app.models.models import Scan, Asset, Finding
from app.services.asset_service import get_asset_tree

router = APIRouter(prefix="/api/domains", tags=["domains"])

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

@router.get("")
async def list_domains(db: AsyncSession = Depends(get_db)):
    stmt = select(Scan.root_domain, func.count(Scan.id).label("scan_count"), func.max(Scan.created_at).label("last_scan")).group_by(Scan.root_domain)
    rows = (await db.execute(stmt)).all()
    return [{"root_domain": r.root_domain, "scan_count": r.scan_count, "last_scan": r.last_scan.isoformat() if r.last_scan else None} for r in rows]

@router.get("/{domain}/history")
async def domain_history(domain: str, db: AsyncSession = Depends(get_db)):
    stmt = select(Scan).where(Scan.root_domain == domain).order_by(Scan.created_at.desc())
    scans = (await db.execute(stmt)).scalars().all()
    return [{"id": s.id, "status": s.status, "profile": s.profile, "created_at": s.created_at.isoformat() if s.created_at else None} for s in scans]
