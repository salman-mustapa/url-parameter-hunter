from __future__ import annotations

from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import Asset, Certificate, Finding, Observation, Parameter, Port, Service, Technology, URL


def _node(asset: Asset, ports_count: int = 0, urls_count: int = 0, techs_count: int = 0) -> dict[str, Any]:
    hostname = asset.hostname or asset.fqdn or asset.fingerprint or "unknown"
    ip = asset.ip
    if not ip and isinstance(asset.metadata_, dict):
        ips = asset.metadata_.get("ips") or []
        if ips and isinstance(ips, list):
            ip = ips[0]

    return {
        "id": asset.id,
        "type": asset.asset_type,
        "asset_type": asset.asset_type,
        "hostname": hostname,
        "fqdn": asset.fqdn or hostname,
        "fingerprint": asset.fingerprint,
        "ip": ip,
        "depth": asset.depth,
        "status": asset.status or "ACTIVE",
        "metadata": asset.metadata_ or {"active": True},
        "ports_count": ports_count,
        "urls_count": urls_count,
        "techs_count": techs_count,
        "first_seen": asset.first_seen.isoformat() if asset.first_seen else None,
        "last_seen": asset.last_seen.isoformat() if asset.last_seen else None,
    }


async def asset_tree(db: AsyncSession, scan_id: str) -> list[dict]:
    rows = (await db.execute(select(Asset).where(Asset.scan_id == scan_id))).scalars().all()
    if not rows:
        return []

    asset_ids = [a.id for a in rows]

    # Query all findings for this scan to map directly to asset nodes
    findings = (await db.execute(select(Finding).where(Finding.scan_id == scan_id))).scalars().all()
    findings_by_asset: dict[str, list] = {}
    for f in findings:
        if f.asset_id:
            findings_by_asset.setdefault(f.asset_id, []).append(f)

    # Query ports, urls, techs counts
    ports = (await db.execute(select(Port).where(Port.asset_id.in_(asset_ids)))).scalars().all()
    ports_by_asset: dict[str, int] = {}
    for p in ports:
        ports_by_asset[p.asset_id] = ports_by_asset.get(p.asset_id, 0) + 1

    urls = (await db.execute(select(URL).where(URL.asset_id.in_(asset_ids)))).scalars().all()
    urls_by_asset: dict[str, int] = {}
    for u in urls:
        urls_by_asset[u.asset_id] = urls_by_asset.get(u.asset_id, 0) + 1

    techs = (await db.execute(select(Technology).where(Technology.asset_id.in_(asset_ids)))).scalars().all()
    techs_by_asset: dict[str, int] = {}
    for t in techs:
        techs_by_asset[t.asset_id] = techs_by_asset.get(t.asset_id, 0) + 1

    sev_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

    by_id: dict[str, dict] = {}
    for a in rows:
        a_findings = findings_by_asset.get(a.id, [])
        f_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        max_sev = None
        cur_max = 0
        for f in a_findings:
            sev = (f.severity or "INFO").upper()
            if sev in f_summary:
                f_summary[sev] += 1
            if sev_rank.get(sev, 0) > cur_max:
                cur_max = sev_rank.get(sev, 0)
                max_sev = sev

        by_id[a.id] = {
            **_node(
                a,
                ports_count=ports_by_asset.get(a.id, 0),
                urls_count=urls_by_asset.get(a.id, 0),
                techs_count=techs_by_asset.get(a.id, 0),
            ),
            "findings_count": len(a_findings),
            "findings_summary": f_summary,
            "max_severity": max_sev,
            "children": [],
        }

    roots: list[dict] = []
    for a in rows:
        node = by_id[a.id]
        if a.parent_id and a.parent_id in by_id and a.parent_id != a.id:
            by_id[a.parent_id]["children"].append(node)
        else:
            roots.append(node)

    # Recursive bottom-up rollup for aggregated summary & max_severity on parent domains
    def rollup(node: dict) -> tuple[dict, Optional[str]]:
        aggregated = dict(node.get("findings_summary", {}))
        cur_max_sev = node.get("max_severity")
        cur_max_rank = sev_rank.get(cur_max_sev, 0) if cur_max_sev else 0

        for child in node.get("children", []):
            child_summary, child_max_sev = rollup(child)
            for k, v in child_summary.items():
                aggregated[k] = aggregated.get(k, 0) + v
            child_rank = sev_rank.get(child_max_sev, 0) if child_max_sev else 0
            if child_rank > cur_max_rank:
                cur_max_rank = child_rank
                cur_max_sev = child_max_sev

        node["findings_summary"] = aggregated
        node["findings_count"] = sum(aggregated.values())
        node["max_severity"] = cur_max_sev
        return aggregated, cur_max_sev

    for r in roots:
        rollup(r)

    return roots


async def asset_detail(db: AsyncSession, asset_id: str) -> dict:
    asset = await db.get(Asset, asset_id)
    if not asset:
        asset = (await db.execute(
            select(Asset).where(
                (Asset.ip == asset_id) | (Asset.hostname == asset_id) | (Asset.fqdn == asset_id)
            )
        )).scalars().first()
    if not asset:
        return {}

    real_asset_id = asset.id
    ports = (await db.execute(select(Port).where(Port.asset_id == real_asset_id))).scalars().all()
    services = (await db.execute(select(Service).where(Service.asset_id == real_asset_id))).scalars().all()
    urls = (await db.execute(select(URL).where(URL.asset_id == real_asset_id))).scalars().all()
    url_ids = [u.id for u in urls]
    params = []
    if url_ids:
        params = (await db.execute(
            select(Parameter).where(Parameter.url_id.in_(url_ids))
        )).scalars().all()
    techs = (await db.execute(
        select(Technology).where(Technology.asset_id == real_asset_id)
    )).scalars().all()
    certs = (await db.execute(
        select(Certificate).where(Certificate.asset_id == real_asset_id)
    )).scalars().all()
    findings = (await db.execute(
        select(Finding).where(Finding.asset_id == real_asset_id)
    )).scalars().all()
    observations = (await db.execute(
        select(Observation).where(Observation.asset_id == real_asset_id)
    )).scalars().all()
    node_data = {
        **_node(asset),
        "asset_type": asset.asset_type,
        "metadata": asset.metadata_ or {},
        "discovered_from": asset.discovered_from or [],
    }
    return {
        "asset": node_data,
        **node_data,
        "ports": [
            {"id": p.id, "port": p.port, "protocol": p.protocol, "state": p.state, "service": p.service, "banner": p.banner}
            for p in ports
        ],
        "services": [
            {"id": s.id, "name": s.name, "product": s.product, "version": s.version, "protocol": s.protocol, "tls_enabled": s.tls_enabled, "banner": s.banner}
            for s in services
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

