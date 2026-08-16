from __future__ import annotations

import asyncio
import logging
import re
import socket
from pathlib import Path
from typing import Any, List, Set, Tuple

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.scanners.base import ScanContext
from app.services.results import result_service

logger = logging.getLogger("scanner.subdomain")


async def _crt_sh(domain: str) -> list[str]:
    """Fetch subdomains from Certificate Transparency (crt.sh)."""
    try:
        async with httpx.AsyncClient(timeout=12.0, follow_redirects=True) as client:
            resp = await client.get(f"https://crt.sh/?q=%.{domain}&output=json")
            if resp.status_code != 200:
                return []
            data = resp.json()
            names: set[str] = set()
            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name and domain in name and not name.startswith("*"):
                        names.add(name)
            return sorted(names)
    except Exception as e:
        logger.debug("crt.sh passive lookup skipped or timed out: %s", e)
        return []


async def _alienvault(domain: str) -> list[str]:
    """Fetch passive DNS dataset from AlienVault OTX."""
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
            resp = await client.get(url)
            if resp.status_code != 200:
                return []
            data = resp.json()
            names: set[str] = set()
            for entry in data.get("passive_dns", []):
                hostname = entry.get("hostname", "").strip().lower()
                if hostname and hostname.endswith(domain):
                    names.add(hostname)
            return list(names)
    except Exception:
        return []


async def _hackertarget(domain: str) -> list[str]:
    """Fetch host records from HackerTarget public search."""
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            resp = await client.get(url)
            if resp.status_code != 200 or "error" in resp.text.lower() or "API count exceeded" in resp.text:
                return []
            names: set[str] = set()
            for line in resp.text.splitlines():
                if "," in line:
                    host = line.split(",")[0].strip().lower()
                    if host and host.endswith(domain):
                        names.add(host)
            return list(names)
    except Exception:
        return []


async def _load_wordlist(domain: str) -> list[str]:
    """Load local subdomain wordlist."""
    path = Path(settings.wordlist_path)
    if not path.exists():
        return []
    names: list[str] = []
    try:
        text = path.read_text(errors="ignore")
        for line in text.splitlines():
            sub = line.strip().lower()
            if sub and not sub.startswith("#") and re.match(r"^[a-z0-9-]+$", sub):
                names.append(f"{sub}.{domain}")
        return names
    except Exception:
        return names


async def _check_host_active(host: str, sem: asyncio.Semaphore) -> Tuple[str, bool, List[str], str | None]:
    """
    Rapid async DNS probe. Returns: (host, is_active, ip_addresses, cname).
    """
    async with sem:
        loop = asyncio.get_running_loop()
        try:
            # Socket getaddrinfo resolution is fast & native
            answers = await loop.run_in_executor(None, socket.getaddrinfo, host, None)
            ips = list(dict.fromkeys(
                addr[4][0] for addr in answers if addr[0] in (socket.AF_INET, socket.AF_INET6)
            ))
            if ips:
                return host, True, ips, None
        except (socket.gaierror, socket.herror, TimeoutError, OSError):
            pass

        # Optional dnspython fallback for CNAME validation
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2.0
            resolver.lifetime = 2.0
            cname_ans = await loop.run_in_executor(None, lambda: resolver.resolve(host, "CNAME"))
            for a in cname_ans:
                target = str(a.target).rstrip(".")
                return host, True, [], target
        except Exception:
            pass

        return host, False, [], None


def _build_hierarchy_chain(subdomain: str, root_domain: str) -> list[str]:
    """
    Given 'a.b.c.example.com' and 'example.com', produces:
    ['c.example.com', 'b.c.example.com', 'a.b.c.example.com']
    """
    if subdomain == root_domain:
        return [root_domain]
    if not subdomain.endswith(f".{root_domain}"):
        return [subdomain]

    prefix = subdomain[: -len(f".{root_domain}")]
    labels = prefix.split(".")
    chain = []
    current = root_domain
    for label in reversed(labels):
        current = f"{label}.{current}"
        chain.append(current)
    return chain


async def run(ctx: ScanContext, db: AsyncSession, root_domain: str) -> None:
    """
    Comprehensive Subdomain Discovery & Active Validation Pipeline:
    1. Multi-source harvesting (CT logs, passive datasets, curated prefixes, wordlist).
    2. Dynamic Active DNS Verification (filters dead candidates).
    3. Hierarchical Asset Graph Construction.
    4. Realtime emission of alive assets.
    """
    await ctx.emit("scan.discovery", f"Starting active subdomain discovery for {root_domain}", severity="info")

    # 1. Ensure Root Asset exists
    root_asset = await result_service.upsert_asset(
        db,
        scan_id=ctx.scan_id,
        asset_type="domain",
        fingerprint=root_domain,
        hostname=root_domain,
        fqdn=root_domain,
        depth=0,
        discovered_from=["user_input"],
        metadata={"root_domain": root_domain, "active": True},
    )
    await db.commit()

    # 2. Gather Candidates from Multiple Passive & Active Sources
    await ctx.emit("discovery.harvest", "Harvesting subdomain datasets from passive & active sources...", root=root_domain)
    
    passive_tasks = [
        _crt_sh(root_domain),
        _alienvault(root_domain),
        _hackertarget(root_domain),
    ]
    if ctx.profile != "passive":
        passive_tasks.append(_load_wordlist(root_domain))

    results = await asyncio.gather(*passive_tasks, return_exceptions=True)
    raw_candidates: Set[str] = {root_domain}
    
    for r in results:
        if isinstance(r, list):
            for name in r:
                name = name.strip().lower().rstrip(".")
                if ctx.scope.host_allowed(name):
                    raw_candidates.add(name)

    # Add high-probability standard prefixes
    if ctx.profile != "passive":
        standard_prefixes = (
            "www", "api", "dev", "staging", "test", "mail", "admin", "portal",
            "app", "m", "cdn", "auth", "sso", "gateway", "beta", "vpn", "webmail",
            "ns1", "ns2", "status", "docs", "graphql", "internal", "secure", "panel"
        )
        for p in standard_prefixes:
            candidate = f"{p}.{root_domain}"
            if ctx.scope.host_allowed(candidate):
                raw_candidates.add(candidate)

    await ctx.emit("discovery.candidates", f"Found {len(raw_candidates)} candidate hostnames. Validating active status...",
                   count=len(raw_candidates))

    # 3. Active DNS Validation
    sem = asyncio.Semaphore(40)  # fast concurrent resolution
    probe_tasks = [_check_host_active(host, sem) for host in raw_candidates]
    probe_results = await asyncio.gather(*probe_tasks, return_exceptions=True)

    active_hosts: dict[str, dict[str, Any]] = {}
    for r in probe_results:
        if isinstance(r, tuple):
            host, is_active, ips, cname = r
            if is_active:
                active_hosts[host] = {"ips": ips, "cname": cname}

    # Always keep root_domain
    if root_domain not in active_hosts:
        active_hosts[root_domain] = {"ips": [], "cname": None}

    await ctx.emit("discovery.validated", f"Identified {len(active_hosts)} ACTIVE & reachable host(s) for {root_domain}",
                   active_count=len(active_hosts), severity="success")

    # 4. Hierarchical Asset Construction
    # Sort hostnames by depth (label count) so parents are always created before children
    sorted_active = sorted(active_hosts.keys(), key=lambda h: h.count("."))
    asset_id_map: dict[str, str] = {root_domain: root_asset.id}

    for host in sorted_active:
        chain = _build_hierarchy_chain(host, root_domain)
        current_parent_id = root_asset.id

        for node_name in chain:
            if node_name == root_domain:
                continue

            node_data = active_hosts.get(node_name, {"ips": [], "cname": None})
            node_ips = node_data["ips"]
            node_cname = node_data["cname"]

            depth = len(node_name.split(".")) - len(root_domain.split("."))
            depth = max(1, depth)

            asset = await result_service.upsert_asset(
                db,
                scan_id=ctx.scan_id,
                asset_type="subdomain",
                fingerprint=node_name,
                hostname=node_name,
                fqdn=node_name,
                ip=node_ips[0] if node_ips else None,
                depth=depth,
                discovered_from=["active_dns", "ct" if node_name in raw_candidates else "hierarchy_inferred"],
                parent_id=current_parent_id,
                metadata={
                    "ips": node_ips,
                    "cname": node_cname,
                    "active": True,
                },
            )
            await db.commit()

            asset_id_map[node_name] = asset.id
            current_parent_id = asset.id

            if node_name == host:
                await ctx.emit(
                    "asset.discovered",
                    f"Active Subdomain: {host}" + (f" -> {', '.join(node_ips)}" if node_ips else (f" (CNAME: {node_cname})" if node_cname else "")),
                    hostname=host,
                    depth=depth,
                    asset_id=asset.id,
                    ips=node_ips,
                    cname=node_cname,
                    severity="info",
                )

    # 5. Recursive Deep Enumeration for 'deep' profile
    if ctx.profile == "deep" and len(active_hosts) < settings.max_assets_per_scan:
        await ctx.emit("discovery.recursive", "Performing recursive deep discovery on identified active subdomains...")
        deep_candidates: Set[str] = set()
        
        for active_sub in list(active_hosts.keys()):
            if active_sub != root_domain:
                for sub_p in ("api", "dev", "v1", "v2", "admin", "auth", "static", "internal"):
                    sub_cand = f"{sub_p}.{active_sub}"
                    if ctx.scope.host_allowed(sub_cand) and sub_cand not in active_hosts:
                        deep_candidates.add(sub_cand)

        if deep_candidates:
            deep_tasks = [_check_host_active(h, sem) for h in deep_candidates]
            deep_results = await asyncio.gather(*deep_tasks, return_exceptions=True)

            for dr in deep_results:
                if isinstance(dr, tuple):
                    h, is_act, ips, cname = dr
                    if is_act:
                        chain = _build_hierarchy_chain(h, root_domain)
                        parent_name = chain[-2] if len(chain) >= 2 else root_domain
                        parent_id = asset_id_map.get(parent_name, root_asset.id)
                        depth = len(h.split(".")) - len(root_domain.split("."))

                        deep_asset = await result_service.upsert_asset(
                            db,
                            scan_id=ctx.scan_id,
                            asset_type="subdomain",
                            fingerprint=h,
                            hostname=h,
                            fqdn=h,
                            ip=ips[0] if ips else None,
                            depth=depth,
                            discovered_from=["recursive_deep", "active_dns"],
                            parent_id=parent_id,
                            metadata={"ips": ips, "cname": cname, "active": True},
                        )
                        await db.commit()
                        asset_id_map[h] = deep_asset.id

                        await ctx.emit(
                            "asset.discovered",
                            f"Active Deep Subdomain: {h}" + (f" -> {', '.join(ips)}" if ips else ""),
                            hostname=h,
                            depth=depth,
                            asset_id=deep_asset.id,
                            ips=ips,
                            severity="info",
                        )


async def discover_subdomains(ctx: ScanContext, db: AsyncSession, root_domain: str) -> list[str]:
    """Helper returning all active discovered hostnames."""
    from app.models.models import Asset
    assets = (await db.execute(
        select(Asset).where(
            Asset.scan_id == ctx.scan_id,
            Asset.asset_type.in_(["domain", "subdomain"]),
        )
    )).scalars().all()
    return [a.hostname for a in assets if a.hostname and ctx.scope.host_allowed(a.hostname)]