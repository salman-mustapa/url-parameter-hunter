from __future__ import annotations

import asyncio
import logging
import re
import socket
from typing import Any, List, Optional
from urllib.parse import urljoin, urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.tools.nmap_adapter import NmapAdapter
from app.core.config import settings
from app.core.profiles import is_deep_profile, is_passive_profile
from app.core.rate_limit import RateLimiter
from app.core.resource_governor import resource_governor
from app.core.resource_guard import resource_guard
from app.core.resource_monitor import ResourceMonitor
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

# Priority web ports scanned first in all modes for quick results
PRIORITY_WEB_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 9000, 9090, 8081]

# Top 100 high-value ports for standard mode (fast, focused scanning)
TOP_100_PORTS = sorted(set([
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465,
    587, 636, 993, 995, 1433, 1521, 1883, 2082, 2083, 2086, 2087,
    2222, 3000, 3001, 3306, 3389, 4000, 4200, 4433, 4443, 5000, 5001,
    5173, 5432, 5555, 5672, 5900, 5985, 5986, 6379, 6443, 7000, 7001,
    8000, 8001, 8008, 8080, 8081, 8082, 8088, 8443, 8500, 8848, 8880,
    8888, 8983, 9000, 9001, 9042, 9090, 9200, 9300, 9443, 10000, 10443,
    11211, 15672, 27017, 27018, 33060, 50051,
]))


async def _grab_banner(host: str, port: int, timeout: float = 1.2) -> str | None:
    """Brief banner grab for service fingerprinting with null byte sanitization."""
    loop = asyncio.get_running_loop()

    def do_grab():
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                if port in (80, 8080, 8443, 8000, 3000, 5000, 2082, 2083, 2086, 2087, 8888, 8880, 9000):
                    safe_host = host.encode("ascii", errors="ignore")[:253]
                    sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + safe_host + b"\r\n\r\n")
                raw = sock.recv(512)
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


async def _probe_http_on_port(ctx: ScanContext, db: AsyncSession, asset_id: str, host: str, port: int) -> None:
    """Perform HTTP probe on non-standard open port to detect web services, redirect mapping, and login forms."""
    if port in (80, 443):
        return

    from app.models.models import URL
    from app.scanners.http import fetch_http

    for proto in ["http", "https"]:
        url = f"{proto}://{host}:{port}/"
        if not ctx.scope.url_allowed(url):
            continue
        try:
            current_url = url
            resp = None
            for _ in range(max(0, settings.nonstandard_http_probe_max_redirects) + 1):
                if not ctx.scope.url_allowed(current_url):
                    await ctx.emit(
                        "scope.redirect_blocked",
                        f"Blocked out-of-scope redirect while probing {url}.",
                        source_url=url,
                        blocked_url=current_url,
                        severity="warn",
                    )
                    resp = None
                    break
                resp = await fetch_http(
                    current_url,
                    timeout=min(5.0, settings.http_timeout_seconds),
                    max_bytes=max(32768, settings.nonstandard_http_probe_max_bytes),
                )
                if resp is None:
                    break
                if resp.status_code not in (301, 302, 303, 307, 308):
                    break
                location = resp.headers.get("location")
                if not location:
                    break
                next_url = urljoin(current_url, location)
                if next_url == current_url:
                    break
                current_url = next_url

            if resp is None:
                continue
            if resp.status_code < 500:
                detected_url = current_url
                if not ctx.scope.url_allowed(detected_url):
                    continue
                body = resp.text.lower()
                headers_str = "".join(f"{k}: {v}\n" for k, v in resp.headers.items()).lower()

                content_type = "web_page"
                tech = None
                if any(k in body for k in ["pma_username", "pma_password", "welcome to phpmyadmin", "phpmyadmin"]):
                    tech = "phpMyAdmin"
                    content_type = "login_form"
                elif any(k in body for k in ["jenkins", "j_username", "j_password"]):
                    tech = "Jenkins"
                    content_type = "login_form"
                elif any(k in body or k in headers_str for k in ["webmin", "session login", "mini_httpd"]):
                    tech = "Webmin"
                    content_type = "login_form"
                elif any(k in body for k in ["tomcat", "manager app", "tomcat manager"]):
                    tech = "Tomcat"
                    content_type = "login_form"
                elif "login" in body and ("username" in body or "password" in body or "email" in body):
                    content_type = "login_form"

                server_hdr = resp.headers.get("server", "")
                if server_hdr:
                    await ctx.emit(
                        "tech.identified",
                        f"Technology identified on {host}:{port}: Server Banner: {server_hdr}",
                        host=host,
                        port=port,
                        technology=server_hdr,
                    )

                if tech:
                    await ctx.emit(
                        "tech.identified",
                        f"Technology identified on {host}:{port}: {tech}",
                        host=host,
                        port=port,
                        technology=tech,
                    )

                # Emit http.service.discovered event
                await ctx.emit(
                    "http.service.discovered",
                    f"HTTP Service discovered on {host}:{port} ({detected_url})",
                    host=host,
                    port=port,
                    url=detected_url,
                    content_type=content_type,
                    technology=tech,
                    severity="info",
                )

                # Save to DB
                existing_url = (await db.execute(
                    select(URL).where(URL.asset_id == asset_id, URL.url == detected_url)
                )).scalar_one_or_none()

                if not existing_url:
                    parsed_det = urlparse(detected_url)
                    new_url = URL(
                        asset_id=asset_id,
                        url=detected_url,
                        path=parsed_det.path or "/",
                        status_code=resp.status_code,
                        content_type=content_type,
                    )
                    db.add(new_url)
                    await db.flush()

                credential_option = ctx.options.get("credential_audit")
                credential_audit_enabled = (
                    bool(credential_option)
                    if credential_option is not None
                    else settings.credential_audit_enabled
                    or ctx.profile == "adversary_simulation"
                )

                # Credential checks are opt-in except in explicitly authorized adversary simulation.
                if content_type == "login_form" and credential_audit_enabled:
                    from app.validation.brute_force import controlled_brute_force_validator
                    from app.services.results import result_service
                    from app.validation.result import NormalizedValidationResult

                    brute_cands = []
                    if tech == "phpMyAdmin":
                        brute_cands = await controlled_brute_force_validator.validate_phpmyadmin(
                            detected_url,
                            max_attempts=settings.credential_audit_max_attempts,
                            delay_seconds=settings.credential_audit_delay_seconds,
                        )
                    else:
                        brute_cands = await controlled_brute_force_validator.validate_login_portal(
                            detected_url,
                            max_attempts=settings.credential_audit_max_attempts,
                            delay_seconds=settings.credential_audit_delay_seconds,
                        )

                    for cand in brute_cands:
                        norm_res = NormalizedValidationResult(
                            adapter_name="controlled_brute_force",
                            vulnerability_type=cand.finding_type,
                            title=cand.title,
                            severity=cand.severity,
                            confidence=cand.confidence,
                            evidence_level=cand.evidence_level,
                            target_host=host,
                            endpoint_url=cand.url,
                            cwe_id="CWE-287" if cand.finding_type == "default_credentials" else "CWE-307",
                            description=f"Authentication policy validation on non-standard port login form {cand.url}: {cand.title}.",
                            impact_matrix=cand.impact_matrix,
                            remediation=cand.remediation,
                            poc_command=cand.poc_curl,
                            reproduction_steps=cand.reproduction_steps,
                            request_metadata={"url": cand.url, "technique": cand.technique, "discovery_method": "port_probe"},
                            response_metadata=cand.evidence,
                            actual_result=cand.title,
                            expected_result="Application should enforce rate-limiting / lockout and reject default passwords.",
                        )
                        try:
                            await result_service.upsert_finding(
                                db,
                                scan_id=ctx.scan_id,
                                asset_id=asset_id,
                                finding_type=norm_res.vulnerability_type,
                                title=norm_res.title,
                                severity=norm_res.severity,
                                confidence=norm_res.confidence,
                                evidence_level=norm_res.evidence_level,
                                cwe_id=norm_res.cwe_id,
                                cvss_score=norm_res.cvss_score,
                                description=norm_res.description,
                                impact=norm_res.business_impact or "Credential compromise",
                                technical_details=norm_res.technical_details,
                                remediation=norm_res.remediation,
                                root_cause=norm_res.root_cause or "Default credentials left unchanged.",
                                expected_result=norm_res.expected_result,
                                actual_result=norm_res.actual_result,
                                evidence=norm_res.response_metadata,
                            )
                            logger.info("CONFIRMED PORT SERVICE BRUTE FORCE FINDING on %s:%d: %s", host, port, cand.title)
                        except Exception as save_err:
                            logger.debug("Failed to save port brute force finding: %s", save_err)
                break
        except Exception:
            continue


async def run(ctx: ScanContext, db: AsyncSession, root_domain: str) -> None:
    """Async High-Performance Port & Service Scanner (§12, §37)."""
    if is_passive_profile(ctx.profile):
        return

    await ctx.emit("scan.port", f"Starting comprehensive port and service discovery for {root_domain}", severity="info")

    assets = (await db.execute(
        select(Asset).where(
            Asset.scan_id == ctx.scan_id,
            Asset.asset_type.in_(["domain", "subdomain", "ip"]),
        )
    )).scalars().all()

    # Cap hosts scanned to keep runtime sane; prioritize root + shallow depth
    target_host = str(ctx.options.get("target_host") or root_domain).lower()
    assets = sorted(
        assets,
        key=lambda a: (
            0 if (a.hostname or a.fqdn or "").lower() == target_host else 1,
            a.depth,
            a.hostname or a.fqdn or a.ip or "",
        ),
    )[: settings.max_port_hosts]
    # Use focused port list for standard mode, full list for deep/full
    if is_deep_profile(ctx.profile):
        ports_to_scan = DEEP_PORTS
        timeout = settings.port_timeout_seconds
    elif ctx.profile == "standard":
        ports_to_scan = TOP_100_PORTS
        timeout = min(settings.port_timeout_seconds, 0.8)  # Faster timeout for standard
    else:
        ports_to_scan = sorted(COMMON_PORTS.keys())
        timeout = min(settings.port_timeout_seconds, 0.8)

    ports_to_scan = [port for port in ports_to_scan if ctx.scope.port_allowed(port)]
    # Reorder: priority web ports first for quick results
    priority_set = set(PRIORITY_WEB_PORTS)
    priority_ports = [p for p in ports_to_scan if p in priority_set]
    other_ports = [p for p in ports_to_scan if p not in priority_set]
    ports_to_scan = priority_ports + other_ports

    limiter = ctx.rate_limiter if ctx.options.get("engagement") else RateLimiter(settings.port_rps)
    requested_asset_concurrency = min(settings.max_concurrent_hosts, settings.max_port_hosts)
    asset_concurrency = ResourceMonitor.calculate_optimal_concurrency(
        max(1, requested_asset_concurrency)
    )
    asset_sem = asyncio.Semaphore(max(1, asset_concurrency))
    port_probe_sem = asyncio.Semaphore(max(1, settings.max_concurrent_port_probes))
    service_validation_sem = asyncio.Semaphore(
        max(1, settings.max_concurrent_service_validations)
    )

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
                    found_ips = [ip for ip in found_ips if ctx.scope.ip_allowed(ip)]
                    if found_ips:
                        resolved_ip = found_ips[0]
                except Exception:
                    pass

            if resolved_ip and not ctx.scope.ip_allowed(resolved_ip):
                await ctx.emit(
                    "scope.ip_blocked",
                    f"Resolved address blocked by network scope policy for {target_host}.",
                    host=target_host,
                    severity="warn",
                )
                return

            probe_target = hostname or resolved_ip
            if not probe_target:
                return

            await ctx.emit("scan.port", f"Scanning {len(ports_to_scan)} port(s) on target {target_host} ({resolved_ip or 'resolving'})...", host=target_host)

            open_ports: list[int] = []

            async def probe_single(p: int):
                if not ctx.scope.port_allowed(p):
                    return
                async with port_probe_sem:
                    await limiter.wait()
                    is_open = await _check_port(probe_target, p, timeout)
                    if not is_open and resolved_ip and resolved_ip != probe_target:
                        is_open = await _check_port(resolved_ip, p, timeout)
                    if is_open:
                        open_ports.append(p)
                        await ctx.emit(
                            "scan.port",
                            f"Open port detected early: {target_host}:{p}/tcp",
                            host=target_host,
                            port=p,
                            severity="info",
                        )

            chunk_size = max(1, settings.max_concurrent_port_probes)
            for i in range(0, len(ports_to_scan), chunk_size):
                if not resource_governor.should_admit_task(is_high_priority=True):
                    await asyncio.sleep(0.2)
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

            if open_ports:
                from app.orchestration.cve_pipeline import (
                    trigger_host_nmap_vuln_pipeline,
                    trigger_immediate_cve_pipeline,
                )

                async def validate_service(port_number: int) -> None:
                    async with service_validation_sem:
                        await trigger_immediate_cve_pipeline(
                            ctx, asset_id, probe_target, resolved_ip, port_number
                        )

                async def validate_services() -> None:
                    if not ctx.options.get("service_validation", False):
                        return
                    await asyncio.gather(
                        *(validate_service(p) for p in sorted(set(open_ports))),
                        return_exceptions=True,
                    )

                async def probe_http_services() -> None:
                    non_std_ports = [p for p in open_ports if p not in (80, 443)]
                    if not non_std_ports:
                        return
                    await ctx.emit(
                        "scan.port",
                        f"Starting HTTP probing on {len(non_std_ports)} non-standard port(s) for technology and redirect detection...",
                        host=target_host,
                    )
                    async with AsyncSessionLocal() as s_db2:
                        for p in non_std_ports:
                            try:
                                await _probe_http_on_port(ctx, s_db2, asset_id, target_host, p)
                            except Exception as probe_err:
                                logger.debug("HTTP probe error on %s:%d: %s", target_host, p, probe_err)
                        await s_db2.commit()

                await asyncio.gather(
                    trigger_host_nmap_vuln_pipeline(ctx, asset_id, probe_target, open_ports),
                    validate_services(),
                    probe_http_services(),
                    return_exceptions=True,
                )

    tasks = [_scan_single_asset(a.id, a.hostname, a.fqdn, a.ip) for a in assets]
    await asyncio.gather(*tasks, return_exceptions=True)


def port_rps(ctx: ScanContext) -> int:
    base = getattr(settings, "port_rps", 250)
    return base // (2 if is_deep_profile(ctx.profile) else 1)
