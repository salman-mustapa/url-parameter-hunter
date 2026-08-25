from __future__ import annotations

import asyncio
import logging
import re
import socket
from typing import Any, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.tools.nmap_adapter import NmapAdapter
from app.core.config import settings
from app.core.rate_limit import RateLimiter
from app.core.resource_guard import resource_guard
from app.core.sanitizer import clean_banner, sanitize_text
from app.models.models import Asset, Port, Service
from app.scanners.base import ScanContext

logger = logging.getLogger("scanner.port")

COMMON_PORTS = {
    # Web & HTTP/HTTPS Services
    80: "http",
    443: "https",
    8080: "http-proxy",
    8443: "https-alt",
    8000: "http-alt",
    8001: "http-alt",
    8008: "http-alt",
    8081: "http-alt",
    8082: "http-alt",
    8088: "http-alt",
    8888: "http-alt",
    8880: "cpanel-http",
    9000: "http-alt",
    9090: "http-mgmt",
    9443: "https-alt",
    10443: "https-alt",
    4433: "https-alt",
    4443: "https-alt",
    # Web Hosting, cPanel, WHM, Plesk, Webmin
    2082: "cpanel",
    2083: "cpanel-ssl",
    2086: "whm",
    2087: "whm-ssl",
    2095: "webmail",
    2096: "webmail-ssl",
    10000: "webmin",
    # Remote Administration
    22: "ssh",
    2222: "ssh-alt",
    23: "telnet",
    3389: "rdp",
    5900: "vnc",
    5901: "vnc-1",
    5985: "winrm-http",
    5986: "winrm-https",
    # File & Network Services
    21: "ftp",
    20: "ftp-data",
    53: "dns",
    69: "tftp",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    445: "microsoft-ds",
    389: "ldap",
    636: "ldaps",
    # Mail & Messaging
    25: "smtp",
    465: "smtps",
    587: "submission",
    110: "pop3",
    995: "pop3s",
    143: "imap",
    993: "imaps",
    5672: "rabbitmq",
    15672: "rabbitmq-mgmt",
    1883: "mqtt",
    8883: "mqtts",
    # Databases & Caches
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    33060: "mysqlx",
    5432: "postgresql",
    6379: "redis",
    9200: "elasticsearch",
    9300: "elasticsearch-node",
    11211: "memcached",
    27017: "mongodb",
    27018: "mongodb",
    9042: "cassandra",
    5984: "couchdb",
    # App Runtimes & Microservices
    3000: "node-dev",
    3001: "node-dev",
    4000: "http-alt",
    4200: "angular-dev",
    5000: "flask-dev",
    5001: "flask-ssl",
    5173: "vite-dev",
    7001: "weblogic",
    7002: "weblogic-ssl",
    8500: "consul",
    8848: "nacos",
    2181: "zookeeper",
    2375: "docker-plain",
    2376: "docker-tls",
    6443: "kubernetes-api",
    50051: "grpc",
}

# Standard Nmap Top 1000 TCP Ports list extension for deep profile
TOP_EXTENDED_PORTS = [
    1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 67, 68, 69, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90,
    99, 100, 106, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161, 162, 163, 179, 199, 211, 212, 222, 254, 255, 259, 264,
    280, 301, 306, 311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500, 512, 513, 514,
    515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636, 646, 648, 666, 667, 668, 683, 687, 691,
    700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902, 903, 911,
    912, 981, 987, 990, 992, 993, 995, 1000, 1001, 1002, 1008, 1010, 1025, 1026, 1027, 1028, 1029, 1030, 1080, 1110, 1122, 1144,
    1155, 1194, 1234, 1352, 1433, 1434, 1500, 1503, 1521, 1524, 1533, 1556, 1604, 1720, 1723, 1755, 1761, 1801, 1883, 1900, 1935,
    1998, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2105, 2171,
    2181, 2222, 2301, 2375, 2376, 2383, 2401, 2601, 2602, 2604, 2605, 2607, 2608, 2717, 2869, 3000, 3001, 3002, 3003, 3005, 3050,
    3074, 3128, 3260, 3268, 3269, 3306, 3307, 3333, 3389, 3689, 3690, 4000, 4001, 4045, 4111, 4125, 4200, 4300, 4433, 4443, 4444,
    4567, 4899, 5000, 5001, 5002, 5004, 5005, 5050, 5060, 5100, 5173, 5190, 5222, 5269, 5357, 5432, 5555, 5631, 5666, 5672, 5800,
    5900, 5901, 5985, 5986, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009, 6101, 6106, 6112, 6379, 6443, 6667, 7000, 7001,
    7002, 7070, 7777, 8000, 8001, 8008, 8010, 8080, 8081, 8082, 8085, 8086, 8087, 8088, 8089, 8090, 8181, 8200, 8282, 8300, 8443,
    8500, 8848, 8880, 8888, 8983, 9000, 9001, 9002, 9042, 9080, 9090, 9091, 9100, 9200, 9300, 9443, 9999, 10000, 10443, 11211,
    15672, 27017, 27018, 50051, 50000, 61616
]

DEEP_PORTS = sorted(set(list(range(1, 1025)) + TOP_EXTENDED_PORTS + list(COMMON_PORTS.keys())))


async def _grab_banner(host: str, port: int, timeout: float = 1.2) -> str | None:
    """Brief banner grab for service fingerprinting with null byte sanitization."""
    loop = asyncio.get_running_loop()

    def do_grab():
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.settimeout(timeout)
            if port in (80, 8080, 8443, 8000, 3000, 5000, 2082, 2083, 2086, 2087, 8888, 8880, 9000):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            elif port in (21, 25, 110, 143):
                pass
            raw = s.recv(512)
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
        conn = await asyncio.wait_for(future, timeout=timeout + 0.3)
        conn.close()
        return True
    except Exception:
        return False


async def run(ctx: ScanContext, db: AsyncSession, root_domain: str) -> None:
    """Async High-Performance Port & Service Scanner (§12, §37)."""
    if ctx.profile == "passive":
        return

    await ctx.emit("scan.port", f"Starting comprehensive port and service discovery for {root_domain}", severity="info")

    assets = (await db.execute(
        select(Asset).where(
            Asset.scan_id == ctx.scan_id,
            Asset.asset_type.in_(["domain", "subdomain", "ip"]),
        )
    )).scalars().all()

    # Cap hosts scanned to keep runtime sane; prioritize root + shallow depth
    assets = sorted(assets, key=lambda a: a.depth)[: settings.max_port_hosts]
    ports_to_scan = DEEP_PORTS if ctx.profile == "deep" else sorted(COMMON_PORTS.keys())
    timeout = settings.port_timeout_seconds
    limiter = RateLimiter(settings.port_rps)
    asset_sem = asyncio.Semaphore(10)

    from app.core.db import AsyncSessionLocal

    async def _scan_single_asset(asset_id: str, hostname: Optional[str], fqdn: Optional[str], ip_addr: Optional[str]):
        target_host = hostname or fqdn or ip_addr
        if not target_host or not ctx.scope.host_allowed(target_host):
            return

        async with asset_sem:
            resolved_ip = ip_addr
            found_ips = []
            if not resolved_ip and hostname:
                try:
                    loop = asyncio.get_running_loop()
                    addr_info = await loop.run_in_executor(None, socket.getaddrinfo, hostname, None)
                    found_ips = list(dict.fromkeys(
                        a[4][0] for a in addr_info if a[0] in (socket.AF_INET, socket.AF_INET6)
                    ))
                    if found_ips:
                        resolved_ip = found_ips[0]
                except Exception:
                    pass

            probe_target = hostname or resolved_ip
            if not probe_target:
                return

            await ctx.emit("scan.port", f"Scanning {len(ports_to_scan)} port(s) on target {target_host} ({resolved_ip or 'resolving'})...", host=target_host)

            open_ports: list[int] = []

            async def probe_single(p: int):
                await limiter.wait()
                is_open = await _check_port(probe_target, p, timeout)
                if not is_open and resolved_ip and resolved_ip != probe_target:
                    is_open = await _check_port(resolved_ip, p, timeout)
                if is_open:
                    open_ports.append(p)

            chunk_size = 60
            for i in range(0, len(ports_to_scan), chunk_size):
                chunk = ports_to_scan[i:i + chunk_size]
                await asyncio.gather(*[probe_single(p) for p in chunk], return_exceptions=True)

            nmap_services: dict[int, str] = {}
            if open_ports:
                try:
                    nmap_adapter = NmapAdapter()
                    if nmap_adapter._binary_path:
                        ports_str = ",".join(str(p) for p in open_ports)
                        nmap_res = await nmap_adapter.execute({"host": probe_target, "ports": ports_str})
                        for p_info in nmap_res.get("open_ports", []):
                            if p_info.get("service") and p_info.get("service") != "unknown":
                                nmap_services[p_info["port"]] = p_info["service"]
                except Exception as nm_err:
                    logger.debug("Nmap adapter fallback for %s: %s", probe_target, nm_err)

            resource_guard.reclaim_memory()

            async with AsyncSessionLocal() as s_db:
                if resolved_ip and found_ips:
                    ast = await s_db.get(Asset, asset_id)
                    if ast:
                        ast.ip = resolved_ip
                        meta = dict(ast.metadata_ or {})
                        meta["ips"] = found_ips
                        ast.metadata_ = meta

                if not open_ports:
                    if resolved_ip and found_ips:
                        await s_db.commit()
                    return

                for port in sorted(open_ports):
                    service = nmap_services.get(port) or COMMON_PORTS.get(port, "unknown")
                    banner = await _grab_banner(probe_target, port, timeout=1.2) if port in (21, 22, 23, 25, 80, 110, 143, 443, 2082, 2083, 3306, 5432, 6379, 8080, 8443) else None

                    existing_port = (await s_db.execute(
                        select(Port).where(
                            Port.asset_id == asset_id,
                            Port.port == port,
                            Port.protocol == "tcp",
                        )
                    )).scalar_one_or_none()

                    if not existing_port:
                        new_port = Port(
                            asset_id=asset_id,
                            ip=resolved_ip,
                            port=port,
                            protocol="tcp",
                            state="open",
                            service=service,
                            banner=banner,
                        )
                        s_db.add(new_port)
                        await s_db.flush()
                        port_id = new_port.id
                    else:
                        if banner and not existing_port.banner:
                            existing_port.banner = banner
                        if service != "unknown" and (not existing_port.service or existing_port.service == "unknown"):
                            existing_port.service = service
                        port_id = existing_port.id

                    is_tls = port in (443, 8443, 2083, 2087, 2096, 993, 995, 8883, 5986, 6443, 2376, 10443, 4433, 4443)
                    existing_svc = (await s_db.execute(
                        select(Service).where(Service.asset_id == asset_id, Service.port_id == port_id)
                    )).scalar_one_or_none()

                    if not existing_svc:
                        s_db.add(Service(
                            asset_id=asset_id,
                            port_id=port_id,
                            name=service,
                            protocol="tcp",
                            tls_enabled=is_tls,
                            banner=banner,
                            metadata_={"port": port, "banner": banner},
                        ))

                    await ctx.emit(
                        "port.open",
                        f"Port OPEN: {target_host}:{port}/tcp ({service})" + (f" - {banner[:40]}" if banner else ""),
                        hostname=target_host,
                        port=port,
                        protocol="tcp",
                        state="open",
                        service=service,
                        banner=banner,
                        asset_id=asset_id,
                        severity="info",
                    )

                await s_db.commit()

    tasks = [_scan_single_asset(a.id, a.hostname, a.fqdn, a.ip) for a in assets]
    await asyncio.gather(*tasks, return_exceptions=True)


def port_rps(ctx: ScanContext) -> int:
    base = getattr(settings, "port_rps", 250)
    return base // (2 if ctx.profile == "deep" else 1)
