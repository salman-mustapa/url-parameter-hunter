"""Dynamic Multi-Source Subdomain Enumeration & Active Recon Pipeline (V5 §5, §6, §36).

Key Capabilities:
1. Multi-Source Passive Harvesting (crt.sh, AlienVault OTX, HackerTarget, Anubis, Archive.org DNS, RapidDNS).
2. Wildcard DNS Detection & Filtering (eliminating false active subdomains on catch-all domains).
3. Smart Permutation & Alter-DNS Mutation Engine.
4. Fast Asynchronous Native DNS Verification.
5. Hierarchical Asset Graph Construction.
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.tools.subfinder_adapter import SubfinderAdapter
from app.core.config import settings
from app.core.profiles import is_deep_profile, is_passive_profile
from app.core.resource_guard import resource_guard
from app.models.models import Asset
from app.scanners.base import ScanContext
from app.services.results import result_service

logger = logging.getLogger("scanner.subdomain")


# ==============================================================================
# 1. Multi-Source Passive Harvesting Modules
# ==============================================================================

async def _crt_sh(domain: str) -> list[str]:
    """Fetch subdomains from Certificate Transparency logs (crt.sh)."""
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
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
        logger.debug("crt.sh passive lookup error: %s", e)
        return []


async def _alienvault(domain: str) -> list[str]:
    """Fetch passive DNS records from AlienVault OTX."""
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
    """Fetch host records from HackerTarget."""
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


async def _anubis(domain: str) -> list[str]:
    """Fetch subdomains from Anubis-DB dataset."""
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
            url = f"https://jldc.me/anubis/subdomains/{domain}"
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    return [s.strip().lower() for s in data if isinstance(s, str) and s.endswith(domain)]
        return []
    except Exception:
        return []


async def _archive_org(domain: str) -> list[str]:
    """Fetch historical subdomains from Archive.org Wayback CDX."""
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=300"
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                names: set[str] = set()
                for row in data[1:]:
                    if row and len(row) > 0:
                        u = row[0]
                        m = re.search(r"https?://([a-zA-Z0-9_\-\.]+)", u)
                        if m:
                            h = m.group(1).lower().strip()
                            if h.endswith(domain):
                                names.add(h)
                return list(names)
        return []
    except Exception:
        return []


async def _certspotter(domain: str) -> list[str]:
    """Fetch subdomains from CertSpotter CT log aggregator."""
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
            url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
            resp = await client.get(url)
            if resp.status_code != 200:
                return []
            data = resp.json()
            names: set[str] = set()
            for entry in data:
                for dns_name in entry.get("dns_names", []):
                    dns_name = dns_name.strip().lower().lstrip("*.")
                    if dns_name and dns_name.endswith(domain) and not dns_name.startswith("*"):
                        names.add(dns_name)
            return list(names)
    except Exception:
        return []


async def _threatcrowd(domain: str) -> list[str]:
    """Fetch subdomains from ThreatCrowd passive intelligence."""
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
            url = f"https://ci-www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                subdomains = data.get("subdomains", [])
                if isinstance(subdomains, list):
                    return [s.strip().lower() for s in subdomains if isinstance(s, str) and s.endswith(domain)]
        return []
    except Exception:
        return []


async def _urlscan(domain: str) -> list[str]:
    """Fetch subdomains from URLScan.io public submissions."""
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100"
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                names: set[str] = set()
                for r in data.get("results", []):
                    page = r.get("page", {})
                    host = page.get("domain", "") or page.get("hostname", "")
                    if host and host.endswith(domain):
                        names.add(host.strip().lower())
                return list(names)
        return []
    except Exception:
        return []


# Top High-Value Wordlist for Active Subdomain Brute-Forcing (V10 Recon Engine)
TOP_SUBDOMAINS_WORDLIST = [
    # Infrastructure & Environments
    "api", "dev", "staging", "prod", "production", "stage", "test", "beta", "alpha", "demo", "lab", "sandbox",
    "admin", "administrator", "portal", "panel", "cpanel", "whm", "webmail", "mail", "email", "remote",
    "vpn", "sso", "auth", "login", "signin", "identity", "id", "account", "accounts", "user", "users", "member",
    "gateway", "gw", "proxy", "reverse-proxy", "lb", "loadbalancer", "ingress", "edge", "router", "traefik",
    # Academic & University Portals (High Relevance for Siat/Sipadu targets)
    "siat", "sipadu", "sim", "siakad", "sia", "elearning", "lms", "moodle", "classroom", "kuliah", "dosen", "mahasiswa",
    "staff", "pegawai", "kepegawaian", "sdm", "hrd", "alumni", "tracer", "skpi", "pmb", "spmb", "penerimaan", "admisi",
    "akademik", "keuangan", "pembayaran", "bayar", "ukt", "beasiswa", "penelitian", "lppm", "jurnal", "journal", "lib", "perpustakaan",
    "wisuda", "ijazah", "transkrip", "kkn", "magang", "mbkm", "prestasi", "kemahasiswaan", "rektorat", "fakultas",
    # Monitoring & Internal Ops
    "grafana", "kibana", "prometheus", "monitor", "monitoring", "zabbix", "nagios", "datadog", "sentry", "uptime", "status",
    "vault", "consul", "etcd", "jenkins", "gitlab", "github", "git", "jira", "confluence", "wiki", "docs", "doc", "swagger", "openapi",
    "nexus", "artifactory", "registry", "docker", "k8s", "kubernetes", "swarm", "portainer", "rancher", "argo",
    # Databases & Backend Services
    "db", "database", "mysql", "postgres", "postgresql", "redis", "elastic", "elasticsearch", "mongo", "mongodb", "rabbit", "rabbitmq", "kafka",
    "graphql", "rest", "grpc", "ws", "socket", "websocket", "events", "stream", "queue", "worker", "cron", "jobs",
    # Storage & Assets
    "cdn", "static", "assets", "media", "img", "images", "files", "download", "downloads", "upload", "uploads", "storage", "s3", "blob", "data",
    # Business & E-Commerce
    "pay", "payment", "checkout", "billing", "invoice", "shop", "store", "ecommerce", "cart", "order", "orders", "customer", "support", "helpdesk", "ticket",
    # Security & Diagnostics
    "security", "sec", "soc", "siem", "waf", "ids", "audit", "compliance", "cert", "ssl", "ca", "debug", "trace", "testapi",
    # Versions & API Revisions
    "v1", "v2", "v3", "v4", "api-v1", "api-v2", "api-dev", "api-staging", "api-prod", "m", "mobile", "app", "web", "www", "old", "new",
]


async def _load_wordlist(domain: str) -> list[str]:
    """Load embedded 250+ top subdomains combined with external wordlist."""
    names: set[str] = set()

    # 1. Built-in top subdomains
    for sub in TOP_SUBDOMAINS_WORDLIST:
        names.add(f"{sub}.{domain}")

    # 2. External wordlist if configured
    path = Path(settings.wordlist_path)
    if path.exists():
        try:
            text = path.read_text(errors="ignore")
            for line in text.splitlines():
                sub = line.strip().lower()
                if sub and not sub.startswith("#") and re.match(r"^[a-z0-9-]+$", sub):
                    names.add(f"{sub}.{domain}")
        except Exception:
            pass

    return list(names)


# ==============================================================================
# 2. Wildcard DNS Detection & DNS Probe
# ==============================================================================

async def _detect_wildcard_dns(root_domain: str) -> Tuple[bool, Set[str]]:
    """Checks if root domain has Wildcard DNS catch-all enabled by testing random canaries."""
    loop = asyncio.get_running_loop()
    wildcard_ips: Set[str] = set()
    test_canaries = [
        f"wildcard_canary_chk_{uuid.uuid4().hex[:8]}.{root_domain}",
        f"wildcard_canary_chk_{uuid.uuid4().hex[:8]}.{root_domain}",
    ]

    for canary in test_canaries:
        try:
            answers = await loop.run_in_executor(None, socket.getaddrinfo, canary, None)
            for addr in answers:
                if addr[0] in (socket.AF_INET, socket.AF_INET6):
                    wildcard_ips.add(addr[4][0])
        except (socket.gaierror, socket.herror, OSError):
            pass

    is_wildcard = len(wildcard_ips) > 0
    if is_wildcard:
        logger.warning("Wildcard DNS detected on %s (Catch-all IP: %s)", root_domain, wildcard_ips)
    return is_wildcard, wildcard_ips


async def _check_host_active(
    host: str,
    sem: asyncio.Semaphore,
    wildcard_ips: Set[str],
) -> Tuple[str, bool, List[str], str | None]:
    """Rapid async DNS resolution with wildcard filtering."""
    async with sem:
        loop = asyncio.get_running_loop()
        try:
            answers = await loop.run_in_executor(None, socket.getaddrinfo, host, None)
            ips = list(dict.fromkeys(
                addr[4][0] for addr in answers if addr[0] in (socket.AF_INET, socket.AF_INET6)
            ))
            if ips:
                # If wildcard DNS is enabled and all resolved IPs match the wildcard catch-all, filter out
                if wildcard_ips and set(ips).issubset(wildcard_ips) and host.count(".") > 1:
                    return host, False, [], None
                return host, True, ips, None
        except (socket.gaierror, socket.herror, TimeoutError, OSError):
            pass

        # Fallback CNAME check
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
    """Builds hierarchical ancestry chain from root_domain to subdomain."""
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


def _generate_smart_permutations(discovered_subs: Set[str], root_domain: str) -> Set[str]:
    """Generates intelligent mutations based on discovered active subdomain prefixes."""
    mutations: Set[str] = set()
    prefixes = ("dev", "staging", "test", "api", "v1", "v2", "admin", "auth", "sso", "internal", "secure", "vpn", "gateway")

    for sub in discovered_subs:
        if sub == root_domain:
            continue
        base_label = sub.split(".")[0]
        for p in prefixes:
            mutations.add(f"{p}-{base_label}.{root_domain}")
            mutations.add(f"{base_label}-{p}.{root_domain}")
            mutations.add(f"{p}.{sub}")

    return mutations


# ==============================================================================
# 3. Main Discovery Pipeline Orchestrator
# ==============================================================================

async def run(ctx: ScanContext, db: AsyncSession, root_domain: str) -> None:
    """Intelligent Dynamic Subdomain Discovery & Active Graph Construction Pipeline."""
    await ctx.emit("scan.discovery", f"Starting active intelligent subdomain discovery for {root_domain}", severity="info")

    target_host = str(ctx.options.get("target_host") or root_domain).strip().lower()
    include_subdomains = bool(ctx.options.get("include_subdomains", True))

    primary_host = root_domain if include_subdomains else target_host

    # 1. Ensure Primary Root Asset exists
    root_asset = await result_service.upsert_asset(
        db,
        scan_id=ctx.scan_id,
        asset_type="domain" if primary_host == root_domain else "subdomain",
        fingerprint=primary_host,
        hostname=primary_host,
        fqdn=primary_host,
        depth=0,
        discovered_from=["user_input"],
        metadata={"root_domain": root_domain, "active": True},
    )
    await db.commit()

    if not include_subdomains:
        await ctx.emit("scan.discovery", f"Mode Focused Target aktif: Memindai target tunggal '{target_host}'.", severity="info")
        raw_candidates: Set[str] = {target_host}
        wildcard_ips = set()
    else:
        raw_candidates: Set[str] = {root_domain, target_host}
        # 2. Check Wildcard DNS
        is_wildcard, wildcard_ips = await _detect_wildcard_dns(root_domain)
        if is_wildcard:
            await ctx.emit(
                "discovery.wildcard",
                f"Wildcard DNS Detected on {root_domain} (Catch-all IP: {', '.join(wildcard_ips)}). Applying noise filter.",
                severity="warn",
            )
        # 3. Harvest candidates from Multi-Source Passive Engines
        await ctx.emit("discovery.harvest", "Harvesting subdomain intelligence from multi-source datasets...", root=root_domain)

        passive_tasks = [
            _crt_sh(root_domain),
            _alienvault(root_domain),
            _hackertarget(root_domain),
            _anubis(root_domain),
            _archive_org(root_domain),
            _certspotter(root_domain),
            _threatcrowd(root_domain),
            _urlscan(root_domain),
        ]
        if not is_passive_profile(ctx.profile):
            passive_tasks.append(_load_wordlist(root_domain))

        results = await asyncio.gather(*passive_tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, list):
                for name in r:
                    name = name.strip().lower().rstrip(".")
                    if ctx.scope.host_allowed(name):
                        raw_candidates.add(name)

        # Standard High-Probability Prefixes
        if not is_passive_profile(ctx.profile):
            standard_prefixes = (
                "www", "api", "dev", "staging", "test", "mail", "admin", "portal",
                "app", "m", "cdn", "auth", "sso", "gateway", "beta", "vpn", "webmail",
                "ns1", "ns2", "status", "docs", "graphql", "internal", "secure", "panel",
                "checkin", "perpustakaan", "siakad", "elearning", "dashboard"
            )
            for p in standard_prefixes:
                candidate = f"{p}.{root_domain}"
                if ctx.scope.host_allowed(candidate):
                    raw_candidates.add(candidate)

        # 3.5. Execute Subfinder Adapter if available
        try:
            sf_adapter = SubfinderAdapter()
            await ctx.emit(
                "tool.active",
                f"⚡ Subfinder recon adapter active for {root_domain}...",
                tool="subfinder",
                target=root_domain,
                severity="info",
            )
            sf_res = await sf_adapter.execute({"domain": root_domain})
            sf_subs = sf_res.get("subdomains", [])
            for s in sf_subs:
                s_clean = s.strip().lower().rstrip(".")
                if ctx.scope.host_allowed(s_clean):
                    raw_candidates.add(s_clean)
        except Exception as sf_err:
            logger.debug("Subfinder adapter execution fallback: %s", sf_err)

        await ctx.emit(
            "discovery.candidates",
            f"Identified {len(raw_candidates)} candidate hostname(s). Verifying live network connectivity...",
            count=len(raw_candidates),
        )

    # 4. Active Concurrent DNS Verification
    resource_guard.reclaim_memory()
    sem = asyncio.Semaphore(40)
    probe_tasks = [_check_host_active(host, sem, wildcard_ips) for host in raw_candidates]
    probe_results = await asyncio.gather(*probe_tasks, return_exceptions=True)

    active_hosts: dict[str, dict[str, Any]] = {}
    for r in probe_results:
        if isinstance(r, tuple):
            host, is_active, ips, cname = r
            if is_active:
                active_hosts[host] = {"ips": ips, "cname": cname}

    # Ensure primary target host is present
    if primary_host not in active_hosts:
        active_hosts[primary_host] = {"ips": [], "cname": None}

    # 5. Smart Permutation & Alter-DNS (Deep Profile & Recursive Only)
    if include_subdomains and is_deep_profile(ctx.profile) and len(active_hosts) < settings.max_assets_per_scan:
        permutations = _generate_smart_permutations(set(active_hosts.keys()), root_domain)
        new_mutations = [m for m in permutations if m not in active_hosts and ctx.scope.host_allowed(m)]
        if new_mutations:
            await ctx.emit("discovery.permutations", f"Fuzzing {len(new_mutations)} intelligent prefix/suffix mutations...")
            perm_tasks = [_check_host_active(m, sem, wildcard_ips) for m in new_mutations[:50]]
            perm_results = await asyncio.gather(*perm_tasks, return_exceptions=True)
            for pr in perm_results:
                if isinstance(pr, tuple):
                    h, is_act, ips, cname = pr
                    if is_act:
                        active_hosts[h] = {"ips": ips, "cname": cname}

    await ctx.emit(
        "discovery.validated",
        f"Verified {len(active_hosts)} ACTIVE & Reachable asset(s) for {primary_host}",
        active_count=len(active_hosts),
        severity="success",
    )

    # Update Root Asset with its resolved IP & DNS metadata immediately
    root_data = active_hosts.get(primary_host) or active_hosts.get(root_domain) or {"ips": [], "cname": None}
    if root_data["ips"]:
        root_asset.ip = root_data["ips"][0]
        meta = dict(root_asset.metadata_ or {})
        meta.update({
            "ips": root_data["ips"],
            "cname": root_data["cname"],
            "active": True,
            "root_domain": root_domain,
        })
        root_asset.metadata_ = meta
        await db.commit()

    # 6. Hierarchical Asset Graph Construction
    sorted_active = sorted(active_hosts.keys(), key=lambda h: h.count("."))
    asset_id_map: dict[str, str] = {primary_host: root_asset.id, root_domain: root_asset.id}

    for host in sorted_active:
        chain = _build_hierarchy_chain(host, root_domain)
        current_parent_id = root_asset.id

        for node_name in chain:
            if node_name == primary_host or (node_name == root_domain and primary_host == root_domain):
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
                    f"Active Asset: {host}" + (f" -> {', '.join(node_ips)}" if node_ips else (f" (CNAME: {node_cname})" if node_cname else "")),
                    hostname=host,
                    depth=depth,
                    asset_id=asset.id,
                    ips=node_ips,
                    cname=node_cname,
                    severity="info",
                )


async def discover_subdomains(ctx: ScanContext, db: AsyncSession, root_domain: str) -> list[str]:
    """Helper returning all active discovered hostnames."""
    assets = (await db.execute(
        select(Asset).where(
            Asset.scan_id == ctx.scan_id,
            Asset.asset_type.in_(["domain", "subdomain"]),
        )
    )).scalars().all()
    return [a.hostname for a in assets if a.hostname and ctx.scope.host_allowed(a.hostname)]
