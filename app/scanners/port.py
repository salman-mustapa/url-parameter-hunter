from __future__ import annotations

import asyncio
import logging
import socket
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.rate_limit import RateLimiter
from app.models.models import Asset, Port
from app.scanners.base import ScanContext
from app.services.results import result_service

logger = logging.getLogger("scanner.port")

COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    993: "imaps", 995: "pop3s", 1433: "mssql", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
}

DEEP_PORTS = list(range(1, 1025)) + list(COMMON_PORTS.keys())


async def _check_port(host: str, port: int, timeout: float) -> bool:
    try:
        loop = asyncio.get_event_loop()
        future = loop.run_in_executor(None, socket.create_connection, (host, port), timeout)
        conn = await asyncio.wait_for(future, timeout=timeout)
        conn.close()
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, socket.gaierror, OSError):
        return False


async def run(ctx: ScanContext, db: AsyncSession, root_domain: str) -> None:
    await ctx.emit("scan.port", f"Port scanning for {root_domain}")

    assets = (await db.execute(
        select(Asset).where(
            Asset.scan_id == ctx.scan_id,
            Asset.asset_type.in_(["domain", "subdomain"]),
            Asset.ip.isnot(None),
        )
    )).scalars().all()

    # cap hosts scanned to keep runtime sane; prefer root + shallow depth first
    assets = sorted(assets, key=lambda a: a.depth)[: settings.max_port_hosts]

    ports_to_scan = DEEP_PORTS if ctx.profile == "deep" else sorted(COMMON_PORTS.keys())
    timeout = settings.port_timeout_seconds
    limiter = RateLimiter(port_rps(ctx))

    for asset in assets:
        if not asset.ip:
            continue
        open_ports: list[int] = []

        def make_probe(port: int):
            async def probe():
                await limiter.wait()
                if await _check_port(asset.ip, port, timeout):
                    open_ports.append(port)
            return probe

        await asyncio.gather(*[make_probe(p)() for p in ports_to_scan])

        for port in sorted(open_ports):
            service = COMMON_PORTS.get(port, "unknown")
            existing = (await db.execute(
                select(Port).where(Port.asset_id == asset.id, Port.port == port)
            )).scalar_one_or_none()
            if not existing:
                db.add(Port(asset_id=asset.id, ip=asset.ip, port=port, state="open", service=service))
            await ctx.emit("port.open", f"{asset.hostname}:{port}/tcp OPEN",
                           hostname=asset.hostname, port=port, state="open", service=service, asset_id=asset.id)
        await db.commit()


def port_rps(ctx: ScanContext) -> int:
    base = getattr(settings, "port_rps", 200)
    return base // (2 if ctx.profile == "deep" else 1)
