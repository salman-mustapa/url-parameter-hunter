from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.services.database import AsyncSessionLocal
from app.models.models import Asset, Finding, URL, Port
from app.services.asset_service import get_asset_tree

router = APIRouter(prefix="/api/assets", tags=["assets"])

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

@router.get("")
async def list_assets(scan_id: str = Query(...), db: AsyncSession = Depends(get_db)):
    stmt = select(Asset).where(Asset.scan_id == scan_id)
    rows = (await db.execute(stmt)).scalars().all()
    return [{"id": r.id, "type": r.asset_type, "hostname": r.hostname, "ip": r.ip, "depth": r.depth} for r in rows]

@router.get("/{scan_id}/tree")
async def asset_tree(scan_id: str, db: AsyncSession = Depends(get_db)):
    tree = await get_asset_tree(db, scan_id)
    return tree
