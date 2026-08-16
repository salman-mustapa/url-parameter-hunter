from __future__ import annotations

import asyncio
import json
import logging
import ssl
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import tldextract
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.scanners.base import ScanContext
from app.services.results import result_service

logger = logging.getLogger("scanner.subdomain")


async def _crt_sh(domain: str) -> list[str]:
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(f"https://crt.sh/?q=%.{domain}&output=json")
            if resp.status_code != 200:
                return []
            data = resp.json()
            names: set[str] = set()
            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name and domain in name:
                        names.add(name)
            return sorted(names)
    except Exception:
        logger.debug("crt.sh failed", exc_info=True)
        return []


async def _wordlist(domain: str) -> list[str]:
    path = Path(settings.wordlist_path)
    if not path.exists():
        return []
    names: list[str] = []
    try:
        text = path.read_text(errors="ignore")
        for line in text.splitlines():
            sub = line.strip().lower()
            if sub and not sub.startswith("#"):
                names.append(f"{sub}.{domain}")
        return names
    except Exception:
        return names


async def run(ctx: ScanContext, db: AsyncSession, root_domain: str) -> None:
    """Subdomain discovery via crt.sh + wordlist. Creates assets hierarchically."""
    await ctx.emit("scan.discovery", f"Subdomain discovery for {root_domain}")

    # root asset
    root_asset = await result_service.upsert_asset(
        db, scan_id=ctx.scan_id, asset_type="domain", fingerprint=root_domain,
        hostname=root_domain, fqdn=root_domain, depth=0, discovered_from=["user_input"],
        metadata={"root_domain": root_domain},
    )
    await db.commit()

    # gather candidates
    candidates: set[str] = {root_domain}
    tasks = []
    tasks.append(_crt_sh(root_domain))
    if ctx.profile != "passive":
        tasks.append(_wordlist(root_domain))
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            candidates.update(r)

    # add common subdomains for non-passive
    if ctx.profile != "passive":
        for prefix in ("www", "api", "dev", "staging", "mail", "admin"):
            candidates.add(f"{prefix}.{root_domain}")

    # resolve & create assets with hierarchy
    sorted_names = sorted(candidates, key=lambda x: x.count("."))
    for name in sorted_names:
        if name == root_domain:
            continue
        if not ctx.scope.host_allowed(name):
            continue

        parts = name.split(".")
        root_parts = root_domain.split(".")
        depth = max(1, len(parts) - len(root_parts))

        parent_name = root_domain if depth == 1 else ".".join(parts[1:])
        if not parent_name.endswith(root_domain):
            parent_name = root_domain

        parent_asset = await result_service.upsert_asset(
            db, scan_id=ctx.scan_id, asset_type="subdomain", fingerprint=parent_name,
            hostname=parent_name, fqdn=parent_name, depth=depth - 1, discovered_from=["subdomain_discovery"],
            parent_id=root_asset.id if parent_name == root_domain else None,
        )
        await db.commit()

        asset = await result_service.upsert_asset(
            db, scan_id=ctx.scan_id, asset_type="subdomain", fingerprint=name,
            hostname=name, fqdn=name, depth=depth, discovered_from=["ct", "wordlist"],
            parent_id=parent_asset.id,
        )
        await db.commit()

        await ctx.emit("asset.discovered", f"Found subdomain: {name}", hostname=name, depth=depth, asset_id=asset.id)


async def discover_subdomains(ctx: ScanContext, db: AsyncSession, root_domain: str) -> list[str]:
    """Return list of discovered hostnames for use by other scanners."""
    tasks = []
    tasks.append(_crt_sh(root_domain))
    if ctx.profile != "passive":
        tasks.append(_wordlist(root_domain))
    results = await asyncio.gather(*tasks, return_exceptions=True)
    out: set[str] = {root_domain}
    for r in results:
        if isinstance(r, list):
            out.update(r)
    return sorted(h for h in out if ctx.scope.host_allowed(h))