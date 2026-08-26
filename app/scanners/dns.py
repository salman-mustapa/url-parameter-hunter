from __future__ import annotations

import asyncio
import logging
import socket
import re
import httpx
from typing import Any, List, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import Asset
from app.scanners.base import ScanContext
from app.services.results import result_service

logger = logging.getLogger("scanner.dns")


TAKEOVER_SIGNATURES = [
    {
        "service": "GitHub Pages",
        "cname_pattern": r"\.github\.io$",
        "body_patterns": ["There isn't a GitHub Pages site here", "404 Not Found"],
        "severity": "HIGH",
    },
    {
        "service": "AWS S3",
        "cname_pattern": r"s3(-website)?\..*amazonaws\.com$",
        "body_patterns": ["The specified bucket does not exist", "NoSuchBucket", "AccessDenied"],
        "severity": "HIGH",
    },
    {
        "service": "Heroku",
        "cname_pattern": r"\.herokudns\.com$|\.herokuapp\.com$",
        "body_patterns": ["no such app", "herokucdn.com/error-pages/no-such-app.html", "No such app"],
        "severity": "HIGH",
    },
    {
        "service": "Shopify",
        "cname_pattern": r"\.myshopify\.com$",
        "body_patterns": ["Sorry, this shop is currently unavailable", "Only one step left", "no-such-shop"],
        "severity": "HIGH",
    },
    {
        "service": "Zendesk",
        "cname_pattern": r"\.zendesk\.com$",
        "body_patterns": ["Help Center Closed", "no such subdomain", "No such Zendesk account"],
        "severity": "HIGH",
    },
    {
        "service": "Ghost",
        "cname_pattern": r"\.ghost\.io$",
        "body_patterns": ["The thing you were looking for is no longer here", "Ghost.io - No such blog"],
        "severity": "HIGH",
    },
]


async def check_subdomain_takeover(hostname: str, cname: str) -> dict | None:
    """Probes the CNAME host to confirm if a service subdomain takeover is possible."""
    for sig in TAKEOVER_SIGNATURES:
        if re.search(sig["cname_pattern"], cname, re.I):
            for scheme in ("https", "http"):
                try:
                    async with httpx.AsyncClient(timeout=6.0, verify=False, follow_redirects=True) as client:
                        resp = await client.get(f"{scheme}://{hostname}")
                        body_text = resp.text
                        for body_pat in sig["body_patterns"]:
                            if body_pat in body_text:
                                return {
                                    "service": sig["service"],
                                    "cname": cname,
                                    "severity": sig["severity"],
                                    "evidence": body_pat,
                                    "url": f"{scheme}://{hostname}",
                                }
                except Exception:
                    pass
    return None


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


async def _reverse_dns(ip: str) -> str | None:
    """Reverse DNS PTR lookup."""
    loop = asyncio.get_running_loop()
    try:
        host, _, _ = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
        return host
    except Exception:
        return None


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
                await ctx.emit(
                    "observation.recorded",
                    f"External CNAME detected: {asset.hostname} -> {cname}",
                    hostname=asset.hostname,
                    cname=cname,
                    asset_id=asset.id,
                    severity="info",
                )
            
            # Active Subdomain Takeover Validation
            takeover_res = await check_subdomain_takeover(asset.hostname, cname)
            if takeover_res:
                desc = (
                    f"Subdomain {asset.hostname} points via CNAME to {cname}, which appears "
                    f"to be an unused/abandoned {takeover_res['service']} page. This allows "
                    f"an attacker to claim the subdomain and host malicious content."
                )
                remed = (
                    f"Remove the CNAME DNS record pointing to {cname} from your DNS zone editor, "
                    f"or register the domain inside {takeover_res['service']} under your control."
                )
                
                await ctx.emit(
                    "finding.created",
                    f"[HIGH] Subdomain Takeover on {asset.hostname} (Service: {takeover_res['service']}) (Evidence: E3, Score: 85/100)",
                    title=f"Subdomain Takeover on {asset.hostname}",
                    severity="HIGH",
                    url=takeover_res["url"],
                    asset_id=asset.id,
                    evidence_level="E3",
                    evidence_score=85,
                    confidence="CONFIRMED",
                )
                
                await result_service.upsert_finding(
                    db,
                    scan_id=ctx.scan_id,
                    asset_id=asset.id,
                    finding_type="subdomain_takeover",
                    title=f"Subdomain Takeover on {asset.hostname}",
                    severity="HIGH",
                    confidence="CONFIRMED",
                    cwe_id="CWE-15",
                    description=desc,
                    impact="Allows full session hijacking, phishing campaigns, cookie theft, and brand defacement under the target domain.",
                    remediation=remed,
                    technical_details=f"CNAME points to: {cname}\nResponse Signature Matched: {takeover_res['evidence']}\nVerified URL: {takeover_res['url']}",
                    evidence_level="E3",
                    evidence_score=85,
                    evidence={"cname": cname, "service": takeover_res["service"], "url": takeover_res["url"], "matched_signature": takeover_res["evidence"]},
                )

        # Update Asset metadata & IP
        meta = dict(asset.metadata_ or {})
        meta.update({
            "dns_a": a_records,
            "dns_aaaa": aaaa_records,
            "dns_cname": cname_records,
            "dns_mx": dns_data.get("MX", []),
            "dns_txt": dns_data.get("TXT", []),
            "dns_ns": dns_data.get("NS", []),
            "ips": all_ips,
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

            ptr_host = await _reverse_dns(ip)
            await result_service.upsert_asset(
                db,
                scan_id=ctx.scan_id,
                asset_type="ip",
                fingerprint=ip,
                hostname=ptr_host or ip,
                fqdn=ptr_host or ip,
                ip=ip,
                depth=asset.depth + 1,
                parent_id=asset.id,
                discovered_from=["dns_resolution"],
                metadata={
                    "associated_host": asset.hostname,
                    "reverse_dns": ptr_host,
                    "is_ipv6": ":" in ip,
                    "active": True,
                },
            )
            await db.commit()
