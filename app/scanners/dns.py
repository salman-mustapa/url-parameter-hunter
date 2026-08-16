from __future__ import annotations

import asyncio
import logging
import socket
from typing import Any, List, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import Asset
from app.scanners.base import ScanContext
from app.services.results import result_service

logger = logging.getLogger("scanner.dns")


async def _resolve_socket(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        answers = await loop.run_in_executor(None, socket.getaddrinfo, host, None)
        return list(dict.fromkeys(
            addr[4][0] for addr in answers if addr[0] in (socket.AF_INET, socket.AF_INET6)
        ))[:10]
    except Exception:
        return []


async def _query_dns_records(host: str) -> dict[str, list[str]]:
    """Query DNS A, AAAA, CNAME, MX, TXT, NS records with timeout."""
    loop = asyncio.get_running_loop()

    def do_queries() -> dict[str, list[str]]:
        import dns.resolver
        from dns.resolver import NXDOMAIN, NoAnswer

        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 3.0
        records: dict[str, list[str]] = {"A": [], "AAAA": [], "CNAME": [], "MX": [], "TXT": [], "NS": []}

        for qtype in ("A", "AAAA", "CNAME", "MX", "TXT", "NS"):
            try:
                answers = resolver.resolve(host, qtype)
                if qtype == "CNAME":
                    records[qtype] = [str(r.target).rstrip(".") for r in answers]
                elif qtype == "MX":
                    records[qtype] = [f"{r.preference} {str(r.exchange).rstrip('.')}" for r in answers]
                else:
                    records[qtype] = [str(r).strip('"') for r in answers]
            except Exception:
                pass
        return records

    try:
        return await loop.run_in_executor(None, do_queries)
    except Exception:
        return {"A": [], "AAAA": [], "CNAME": [], "MX": [], "TXT": [], "NS": []}


async def run(ctx: ScanContext, db: AsyncSession, root_domain: str) -> None:
    """DNS Enrichment & DNS Asset Mapping."""
    await ctx.emit("scan.dns", f"Enriching DNS records and mapping IPs for {root_domain}", severity="info")

    assets = (await db.execute(
        select(Asset).where(
            Asset.scan_id == ctx.scan_id,
            Asset.asset_type.in_(["domain", "subdomain"]),
        )
    )).scalars().all()

    for asset in assets:
        if not asset.hostname:
            continue

        await ctx.rate_limiter.wait()
        dns_data = await _query_dns_records(asset.hostname)

        # Fallback socket lookup if dnspython returned no A/AAAA
        a_records = dns_data.get("A", [])
        aaaa_records = dns_data.get("AAAA", [])
        cname_records = dns_data.get("CNAME", [])
        
        if not a_records and not aaaa_records:
            sock_ips = await _resolve_socket(asset.hostname)
            for ip in sock_ips:
                if ":" in ip:
                    aaaa_records.append(ip)
                else:
                    a_records.append(ip)

        all_ips = list(dict.fromkeys(a_records + aaaa_records))
        cname = cname_records[0] if cname_records else None

        # Check CNAME Scope & potential takeover observation
        if cname:
            if not ctx.scope.host_allowed(cname):
                # CNAME points out of scope (e.g. AWS S3, Cloudflare, Github Pages, Heroku)
                await ctx.emit(
                    "observation.recorded",
                    f"External CNAME detected: {asset.hostname} -> {cname}",
                    hostname=asset.hostname,
                    cname=cname,
                    asset_id=asset.id,
                    severity="info",
                )

        # Update Asset metadata
        meta = dict(asset.metadata_ or {})
        meta.update({
            "dns_a": a_records,
            "dns_aaaa": aaaa_records,
            "dns_cname": cname_records,
            "dns_mx": dns_data.get("MX", []),
            "dns_txt": dns_data.get("TXT", []),
            "dns_ns": dns_data.get("NS", []),
            "cname": cname,
            "active": bool(all_ips or cname),
        })
        asset.metadata_ = meta

        if all_ips:
            asset.ip = all_ips[0]
            asset.status = "resolved"
        elif cname:
            asset.status = "cname_only"

        await db.commit()

        if all_ips or cname:
            msg = f"DNS: {asset.hostname} -> " + (", ".join(all_ips) if all_ips else f"CNAME {cname}")
            await ctx.emit(
                "dns.resolved",
                msg,
                hostname=asset.hostname,
                a=a_records,
                aaaa=aaaa_records,
                cname=cname,
                mx=dns_data.get("MX", []),
                txt=dns_data.get("TXT", []),
                asset_id=asset.id,
                severity="info",
            )

        # Create distinct IP assets for Attack Surface graph
        for ip in all_ips:
            if not ctx.scope.ip_allowed(ip) and ctx.options.get("strict_scope"):
                continue

            await result_service.upsert_asset(
                db,
                scan_id=ctx.scan_id,
                asset_type="ip",
                fingerprint=ip,
                ip=ip,
                depth=asset.depth + 1,
                parent_id=asset.id,
                discovered_from=["dns_resolution"],
                metadata={
                    "associated_host": asset.hostname,
                    "is_ipv6": ":" in ip,
                },
            )
            await db.commit()
