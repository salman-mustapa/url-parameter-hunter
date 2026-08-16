from __future__ import annotations

import asyncio
import logging
import socket
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import Asset
from app.scanners.base import ScanContext
from app.services.results import result_service

logger = logging.getLogger("scanner.dns")


async def _resolve(host: str, qtype: str = "A") -> list[str]:
    loop = asyncio.get_event_loop()
    try:
        answers = await loop.run_in_executor(None, socket.getaddrinfo, host, None)
        return [addr[4][0] for addr in answers if addr[0] in (socket.AF_INET, socket.AF_INET6)][:10]
    except socket.gaierror:
        return []
    except Exception:
        return []


async def _dns_query(host: str, qtype: str = "A") -> list[str]:
    from dns.resolver import Resolver, NoAnswer, NXDOMAIN, LifetimeTimeout

    resolver = Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    try:
        answers = resolver.resolve(host, qtype)
        return [str(r) for r in answers]
    except (NoAnswer, NXDOMAIN, LifetimeTimeout, Exception):
        return []


async def run(ctx: ScanContext, db: AsyncSession, root_domain: str) -> None:
    await ctx.emit("scan.dns", f"DNS resolution for {root_domain}")

    assets = (await db.execute(
        select(Asset).where(Asset.scan_id == ctx.scan_id, Asset.asset_type.in_(["domain", "subdomain"]))
    )).scalars().all()

    for asset in assets:
        if not asset.hostname:
            continue
        await ctx.rate_limiter.wait()

        a_records = await _dns_query(asset.hostname, "A")
        if not a_records:
            continue

        asset.ip = a_records[0]
        asset.status = "resolved"
        await db.commit()

        await ctx.emit("dns.resolved", f"{asset.hostname} -> {', '.join(a_records)}",
                       hostname=asset.hostname, a=a_records, asset_id=asset.id)

        # create IP assets
        for ip in a_records:
            if not ctx.scope.ip_allowed(ip) and ctx.options.get("strict_scope"):
                continue
            ip_asset = await result_service.upsert_asset(
                db, scan_id=ctx.scan_id, asset_type="ip", fingerprint=ip,
                ip=ip, parent_id=asset.id, discovered_from=["dns"],
                metadata={"a": a_records},
            )
            await db.commit()
