from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import Asset, Port, URL


def _node(asset: Asset) -> dict[str, Any]:
    return {
        "id": asset.id,
        "type": asset.asset_type,
        "hostname": asset.hostname,
        "fqdn": asset.fqdn,
        "ip": asset.ip,
        "depth": asset.depth,
        "status": asset.status,
        "first_seen": asset.first_seen.isoformat() if asset.first_seen else None,
        "last_seen": asset.last_seen.isoformat() if asset.last_seen else None,
    }


async def asset_tree(db: AsyncSession, scan_id: str) -> list[dict]:
    rows = (await db.execute(select(Asset).where(Asset.scan_id == scan_id))).scalars().all()
    by_id: dict[str, dict] = {a.id: {**_node(a), "children": []} for a in rows}
    roots: list[dict] = []
    for a in rows:
        node = by_id[a.id]
        if a.parent_id and a.parent_id in by_id:
            by_id[a.parent_id]["children"].append(node)
        else:
            roots.append(node)
    return roots


async def asset_detail(db: AsyncSession, asset_id: str) -> dict:
    asset = await db.get(Asset, asset_id)
    if not asset:
        return {}
    ports = (await db.execute(select(Port).where(Port.asset_id == asset_id))).scalars().all()
    urls = (await db.execute(select(URL).where(URL.asset_id == asset_id))).scalars().all()
    return {
        **_node(asset),
        "ports": [
            {"port": p.port, "protocol": p.protocol, "state": p.state, "service": p.service, "banner": p.banner}
            for p in ports
        ],
        "urls": [
            {"url": u.url, "scheme": u.scheme, "host": u.host, "port": u.port, "path": u.path,
             "status_code": u.status_code, "content_type": u.content_type, "title": u.title}
            for u in urls
        ],
    }
