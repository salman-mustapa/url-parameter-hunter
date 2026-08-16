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
    import dns.resolver
    from dns.resolver import NXDOMAIN, NoAnswer

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    try:
        answers = resolver.resolve(host, qtype)
        return [str(r) for r in answers]
    except (NoAnswer, NXDOMAIN, dns.resolver.LifetimeTimeout, Exception):
        return []


async def _cname_query(host: str) -> str | None:
    import dns.resolver
    from dns.resolver import NXDOMAIN, NoAnswer

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    try:
        answers = resolver.resolve(host, "CNAME")
        for a in answers:
            return str(a.target).rstrip(".")
    except (NoAnswer, NXDOMAIN, dns.resolver.LifetimeTimeout, Exception):
        return None


async def run(ctx: ScanContext, db: AsyncSession, root_domain: str) -> None:
    await ctx.emit("scan.dns", f"DNS resolution for {root_domain}")

    assets = (await db.execute(
        select(Asset).where(Asset.scan_id == ctx.scan_id, Asset.asset_type.in_(["domain", "subdomain"]))
    )).scalars().all()

    for asset in assets:
        if not asset.hostname:
            continue
        await ctx.rate_limiter.wait()

        cname = await _cname_query(asset.hostname)
        if cname and not ctx.scope.host_allowed(cname):
            await ctx.emit("scope.denied",
                           f"CNAME {asset.hostname} -> {cname} out of scope, skip",
                           hostname=asset.hostname, cname=cname, severity="warn")
            continue
        if cname:
            asset.metadata_ = {**(asset.metadata_ or {}), "cname": cname}

        a_records = await _dns_query(asset.hostname, "A")
        aaaa_records = await _dns_query(asset.hostname, "AAAA")
        if not a_records and not aaaa_records:
            continue

        asset.ip = (a_records or aaaa_records)[0]
        asset.status = "resolved"
        await db.commit()

        await ctx.emit("dns.resolved", f"{asset.hostname} -> {', '.join(a_records or aaaa_records)}",
                       hostname=asset.hostname, a=a_records, aaaa=aaaa_records,
                       cname=cname, asset_id=asset.id)

        # create IP assets
        for ip in (a_records + aaaa_records):
            if not ctx.scope.ip_allowed(ip) and ctx.options.get("strict_scope"):
                continue
            ip_asset = await result_service.upsert_asset(
                db, scan_id=ctx.scan_id, asset_type="ip", fingerprint=ip,
                ip=ip, parent_id=asset.id, discovered_from=["dns"],
                metadata={"a": a_records, "aaaa": aaaa_records},
            )
            await db.commit()
