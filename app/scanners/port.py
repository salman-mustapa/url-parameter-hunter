from __future__ import annotations

import asyncio
import logging
import socket
from typing import Any, List

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.rate_limit import RateLimiter
from app.models.models import Asset, Port
from app.scanners.base import ScanContext

logger = logging.getLogger("scanner.port")

COMMON_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    3000: "http-dev",
    3306: "mysql",
    3389: "rdp",
    5000: "http-alt",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8000: "http-alt",
    8008: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    8888: "http-alt",
    9000: "http-alt",
    9090: "http-mgmt",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}

DEEP_PORTS = list(range(1, 1025)) + sorted(COMMON_PORTS.keys())


from app.core.sanitizer import clean_banner, sanitize_text


async def _grab_banner(host: str, port: int, timeout: float = 1.0) -> str | None:
    """Brief banner grab for service fingerprinting with null byte sanitization."""
    loop = asyncio.get_running_loop()

    def do_grab():
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.settimeout(timeout)
            if port in (80, 8080, 8443, 8000, 3000, 5000):
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            raw = s.recv(256)
            s.close()
            return clean_banner(raw)
        except Exception:
            return None

    try:
        return await loop.run_in_executor(None, do_grab)
    except Exception:
        return None



async def _check_port(host: str, port: int, timeout: float) -> bool:
    loop = asyncio.get_running_loop()
    try:
        future = loop.run_in_executor(None, socket.create_connection, (host, port), timeout)
        conn = await asyncio.wait_for(future, timeout=timeout + 0.2)
        conn.close()
        return True
    except Exception:
        return False


async def run(ctx: ScanContext, db: AsyncSession, root_domain: str) -> None:
    """Async Port Scanner with rate limiting and banner enrichment."""
    if ctx.profile == "passive":
        return

    await ctx.emit("scan.port", f"Starting port scanning for {root_domain}", severity="info")

    assets = (await db.execute(
        select(Asset).where(
            Asset.scan_id == ctx.scan_id,
            Asset.asset_type.in_(["domain", "subdomain"]),
            Asset.ip.isnot(None),
        )
    )).scalars().all()

    # Cap hosts scanned to keep runtime sane; prioritize root + shallow depth
    assets = sorted(assets, key=lambda a: a.depth)[: settings.max_port_hosts]
    ports_to_scan = DEEP_PORTS if ctx.profile == "deep" else sorted(COMMON_PORTS.keys())
    timeout = settings.port_timeout_seconds
    limiter = RateLimiter(port_rps(ctx))

    for asset in assets:
        if not asset.ip:
            continue

        target_host = asset.hostname or asset.ip
        open_ports: list[int] = []

        async def probe_single(p: int):
            await limiter.wait()
            if await _check_port(asset.ip, p, timeout):
                open_ports.append(p)

        # Batch in concurrent chunks to avoid socket exhaustion
        chunk_size = 50
        for i in range(0, len(ports_to_scan), chunk_size):
            chunk = ports_to_scan[i:i + chunk_size]
            await asyncio.gather(*[probe_single(p) for p in chunk], return_exceptions=True)

        for port in sorted(open_ports):
            service = COMMON_PORTS.get(port, "unknown")
            banner = await _grab_banner(asset.ip, port, timeout=1.0) if port in (21, 22, 25, 80, 443, 3306, 6379) else None

            existing = (await db.execute(
                select(Port).where(
                    Port.asset_id == asset.id,
                    Port.port == port,
                    Port.protocol == "tcp",
                )
            )).scalar_one_or_none()

            if not existing:
                db.add(Port(
                    asset_id=asset.id,
                    ip=asset.ip,
                    port=port,
                    protocol="tcp",
                    state="open",
                    service=service,
                    banner=banner,
                ))
            elif banner and not existing.banner:
                existing.banner = banner

            await ctx.emit(
                "port.open",
                f"Port OPEN: {target_host}:{port}/tcp ({service})" + (f" - {banner[:40]}" if banner else ""),
                hostname=target_host,
                port=port,
                protocol="tcp",
                state="open",
                service=service,
                banner=banner,
                asset_id=asset.id,
                severity="info",
            )
        await db.commit()


def port_rps(ctx: ScanContext) -> int:
    base = getattr(settings, "port_rps", 250)
    return base // (2 if ctx.profile == "deep" else 1)
