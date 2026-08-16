from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import Asset, Certificate, Finding, Observation, Parameter, Port, Technology, URL


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
    url_ids = [u.id for u in urls]
    params = []
    if url_ids:
        params = (await db.execute(
            select(Parameter).where(Parameter.url_id.in_(url_ids))
        )).scalars().all()
    techs = (await db.execute(
        select(Technology).where(Technology.asset_id == asset_id)
    )).scalars().all()
    certs = (await db.execute(
        select(Certificate).where(Certificate.asset_id == asset_id)
    )).scalars().all()
    findings = (await db.execute(
        select(Finding).where(Finding.asset_id == asset_id)
    )).scalars().all()
    observations = (await db.execute(
        select(Observation).where(Observation.asset_id == asset_id)
    )).scalars().all()
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
        "parameters": [
            {"name": p.name, "location": p.location, "type": p.type, "confidence": p.confidence}
            for p in params
        ],
        "technologies": [
            {"name": t.name, "version": t.version, "confidence": t.confidence, "evidence": t.evidence}
            for t in techs
        ],
        "certificates": [
            {"hostname": c.hostname, "subject_cn": c.subject_cn, "issuer_cn": c.issuer_cn,
             "not_before": c.not_before.isoformat() if c.not_before else None,
             "not_after": c.not_after.isoformat() if c.not_after else None,
             "san_dns": c.san_dns or [], "fingerprint_sha256": c.fingerprint_sha256,
             "signature_algorithm": c.signature_algorithm}
            for c in certs
        ],
        "findings": [
            {"id": f.id, "title": f.title, "severity": f.severity, "finding_type": f.finding_type,
             "confidence": f.confidence, "status": f.status, "description": f.description,
             "evidence": f.evidence or {}}
            for f in findings
        ],
        "observations": [
            {"id": o.id, "observation_type": o.observation_type, "title": o.title,
             "evidence": o.evidence or {}, "confidence": o.confidence}
            for o in observations
        ],
    }
