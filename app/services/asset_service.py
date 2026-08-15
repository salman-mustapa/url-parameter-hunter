from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.models import Asset
from typing import Dict, List

async def get_asset_tree(db: AsyncSession, scan_id: str) -> List[dict]:
    stmt = select(Asset).where(Asset.scan_id == scan_id)
    rows = (await db.execute(stmt)).scalars().all()
    by_id: Dict[str, dict] = {}
    for r in rows:
        by_id[r.id] = {
            "id": r.id,
            "type": r.asset_type,
            "hostname": r.hostname,
            "ip": r.ip,
            "depth": r.depth,
            "status": r.status,
            "children": [],
        }
    tree: List[dict] = []
    for r in rows:
        node = by_id[r.id]
        if r.parent_id and r.parent_id in by_id:
            by_id[r.parent_id]["children"].append(node)
        else:
            tree.append(node)
    return tree
