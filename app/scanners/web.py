from __future__ import annotations

import asyncio
import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.models import Asset, URL
from app.scanners.http import fetch, extract_title
from app.services.results import result_service

logger = logging.getLogger("scanner.web")

COMMON_PATHS = [
    "/robots.txt", "/sitemap.xml", "/login", "/admin", "/api", "/api/v1",
    "/api/v1/users", "/api/docs", "/swagger", "/swagger-ui.html", "/health",
    "/.env", "/config.php", "/wp-admin", "/.git/HEAD", "/server-status",
    "/graphql", "/.well-known/security.txt", "/backup", "/error", "/status",
]


async def run(ctx: ScanContext, db: AsyncSession, root_domain: str) -> None:
    await ctx.emit("scan.web", f"URL discovery for {root_domain}")

    assets = (await db.execute(
        select(Asset).where(Asset.scan_id == ctx.scan_id, Asset.asset_type.in_(["domain", "subdomain"]))
    )).scalars().all()

    # map hostname -> asset ids for url creation
    for asset in assets:
        host = asset.hostname
        if not host or not ctx.scope.host_allowed(host):
            continue

        base_urls = [f"https://{host}/"]
        existing = (await db.execute(
            select(URL).where(URL.asset_id == asset.id)
        )).scalars().all()
        if existing:
            base_urls = [e.url for e in existing]

        seen: set[str] = {u.rstrip("/") for u in base_urls}
        to_probe: list[str] = []

        for base in base_urls:
            for path in COMMON_PATHS:
                candidate = urljoin(base, path)
                if candidate.rstrip("/") not in seen:
                    seen.add(candidate.rstrip("/"))
                    to_probe.append(candidate)

            # robots.txt -> extract disallowed paths
            robots_url = urljoin(base, "/robots.txt")
            resp = await fetch(robots_url, timeout=settings.http_timeout_seconds)
            if resp and resp.status_code == 200:
                for line in resp.text.splitlines():
                    if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                        p = line.split(":", 1)[1].strip()
                        if p and p != "/":
                            candidate = urljoin(base, p)
                            if candidate.rstrip("/") not in seen:
                                seen.add(candidate.rstrip("/"))
                                to_probe.append(candidate)

        # cap URLs per scan
        url_count = (await db.execute(
            select(URL).where(URL.asset_id == asset.id)
        )).scalars().all()
        cap = settings.max_urls_per_scan
        budget = max(0, cap - len(url_count))
        to_probe = to_probe[:budget]

        open_ports = set()
        for u in base_urls:
            parsed = urlparse(u)
            open_ports.add(parsed.port or (443 if parsed.scheme == "https" else 80))

        checked: set[str] = set()
        for url in to_probe:
            if url in checked:
                continue
            checked.add(url)
            await ctx.rate_limiter.wait()
            resp = await fetch(url, timeout=settings.http_timeout_seconds)
            if resp is None:
                continue
            status = resp.status_code
            parsed = urlparse(url)
            from app.models.models import URL as URLModel
            existing_url = (await db.execute(
                select(URLModel).where(URLModel.asset_id == asset.id, URLModel.url == url)
            )).scalar_one_or_none()
            if not existing_url:
                db.add(URLModel(
                    asset_id=asset.id, url=url, scheme=parsed.scheme, host=host,
                    port=parsed.port or (443 if parsed.scheme == "https" else 80),
                    path=parsed.path or "/", status_code=status,
                    content_type=resp.headers.get("content-type", "")[:200],
                    title=extract_title(resp.text) if resp.text else None,
                ))
            await ctx.emit("url.discovered", f"Discovered {url} [{status}]",
                           url=url, status_code=status, host=host, asset_id=asset.id)

            # parameter extraction from URL query strings
            from app.models.models import Parameter
            if parsed.query:
                for key_value in parsed.query.split("&"):
                    if "=" in key_value:
                        name = key_value.split("=")[0]
                        url_obj = (await db.execute(
                            select(URLModel).where(URLModel.asset_id == asset.id, URLModel.url == url)
                        )).scalar_one_or_none()
                        if url_obj:
                            existing_param = (await db.execute(
                                select(Parameter).where(Parameter.url_id == url_obj.id, Parameter.name == name)
                            )).scalar_one_or_none()
                            if not existing_param:
                                db.add(Parameter(url_id=url_obj.id, name=name, location="query", confidence=0.8))
                            await ctx.emit("parameter.discovered", f"Parameter detected: {name}",
                                           name=name, location="query", url=url, asset_id=asset.id)

            # crawl page for links (max depth)
            if resp.text and len(resp.text) < 500_000:
                for m in re.finditer(r'href=["\']([^"\'#]+)["\']', resp.text, re.IGNORECASE):
                    link = urljoin(url, m.group(1))
                    lp = urlparse(link)
                    if lp.scheme not in ("http", "https"):
                        continue
                    if not ctx.scope.host_allowed(lp.hostname or ""):
                        continue
                    if lp.hostname != host:
                        continue
                    norm = link.rstrip("/")
                    if norm not in seen and len(seen) < cap:
                        seen.add(norm)
                        from app.models.models import URL as URLModel2
                        existing_link = (await db.execute(
                            select(URLModel2).where(URLModel2.asset_id == asset.id, URLModel2.url == link)
                        )).scalar_one_or_none()
                        if not existing_link:
                            db.add(URLModel2(
                                asset_id=asset.id, url=link, scheme=lp.scheme, host=host,
                                port=lp.port or (443 if lp.scheme == "https" else 80),
                                path=lp.path or "/", status_code=None,
                            ))
                        await ctx.emit("url.discovered", f"Discovered {link}", url=link, host=host, asset_id=asset.id)
        await db.commit()