from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, List, Set
from urllib.parse import parse_qs, urljoin, urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import AsyncSessionLocal
from app.core.sanitizer import sanitize_text
from app.models.models import Asset, Parameter, URL
from app.scanners.base import ScanContext
from app.scanners.http import extract_title, fetch_http



logger = logging.getLogger("scanner.web")

DISCOVERY_PATHS = [
    # Metadata & SEO
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    # Common App Endpoints
    "/login",
    "/signin",
    "/register",
    "/auth",
    "/admin",
    "/portal",
    "/dashboard",
    "/search",
    "/download",
    "/upload",
    # API & Docs
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v1/users",
    "/api/v1/auth",
    "/api/v1/status",
    "/api/docs",
    "/docs",
    "/swagger",
    "/swagger/v1/swagger.json",
    "/swagger.json",
    "/openapi.json",
    "/graphql",
    "/graphiql",
    # Health & Telemetry
    "/health",
    "/healthz",
    "/livez",
    "/metrics",
    "/status",
    "/info",
    "/server-status",
    # Potential Sensitive Exposure Checks
    "/.env",
    "/.git/HEAD",
    "/config.php",
    "/config.json",
    "/backup.sql",
    "/backup.zip",
    "/wp-admin",
    "/phpinfo.php",
]


def _extract_parameters_from_url(url_str: str) -> list[tuple[str, str]]:
    """Extracts (param_name, location) from URL query strings."""
    parsed = urlparse(url_str)
    params: list[tuple[str, str]] = []
    if parsed.query:
        qs = parse_qs(parsed.query, keep_blank_values=True)
        for key in qs.keys():
            k = key.strip()
            if k and re.match(r"^[a-zA-Z0-9_\-\.\[\]]+$", k):
                params.append((k, "query"))
    return params


def _extract_form_inputs(html: str) -> list[tuple[str, str]]:
    """Extracts form field parameters from HTML input/select/textarea tags."""
    if not html:
        return []
    params: list[tuple[str, str]] = []
    for m in re.finditer(r'<input[^>]+name=["\']([^"\']+)["\']', html, re.IGNORECASE):
        name = m.group(1).strip()
        if name:
            params.append((name, "body"))
    for m in re.finditer(r'<textarea[^>]+name=["\']([^"\']+)["\']', html, re.IGNORECASE):
        name = m.group(1).strip()
        if name:
            params.append((name, "body"))
    return params


async def crawl_and_discover_asset(ctx: ScanContext, db: AsyncSession, asset: Asset, root_domain: str) -> None:
    """Discovers URLs, Endpoints and Parameters for a single active asset."""
    host = asset.hostname
    if not host or not ctx.scope.host_allowed(host):
        return

    base_urls = [f"https://{host}/", f"http://{host}/"]
    
    # Check existing root probed URLs
    existing_urls = (await db.execute(
        select(URL).where(URL.asset_id == asset.id)
    )).scalars().all()
    if existing_urls:
        base_urls = list({u.url for u in existing_urls})

    seen_urls: Set[str] = {u.rstrip("/") for u in base_urls}
    to_probe: List[str] = []

    for base in base_urls:
        for path in DISCOVERY_PATHS:
            cand = urljoin(base, path)
            norm = cand.rstrip("/")
            if norm not in seen_urls:
                seen_urls.add(norm)
                to_probe.append(cand)

        # Check robots.txt for disallowed or allowed paths
        robots_url = urljoin(base, "/robots.txt")
        resp = await fetch_http(robots_url, timeout=5.0)
        if resp and resp.status_code == 200 and resp.text:
            for line in resp.text.splitlines():
                if ":" in line:
                    prefix, val = line.split(":", 1)
                    if prefix.strip().lower() in ("disallow", "allow"):
                        p = val.strip()
                        if p and p != "/" and not p.startswith("*"):
                            cand = urljoin(base, p)
                            norm = cand.rstrip("/")
                            if norm not in seen_urls:
                                seen_urls.add(norm)
                                to_probe.append(cand)

    # Budget URLs per host
    cap = min(len(to_probe), settings.max_urls_per_scan // max(1, settings.max_web_hosts))
    to_probe = to_probe[:cap]

    sem = asyncio.Semaphore(10)

    async def probe_endpoint(target_url: str):
        async with sem:
            await ctx.rate_limiter.wait()
            resp = await fetch_http(target_url, timeout=settings.http_timeout_seconds)
            if resp is None:
                return

            status = resp.status_code
            parsed = urlparse(target_url)
            port_num = parsed.port or (443 if parsed.scheme == "https" else 80)
            title = extract_title(resp.text) if resp.text else None
            content_type = (resp.headers.get("content-type") or "").split(";")[0].strip()[:100]

            async with AsyncSessionLocal() as session:
                # Upsert URL
                clean_target_url = sanitize_text(target_url)
                clean_title = sanitize_text(title)
                clean_ct = sanitize_text(content_type)
                clean_path = sanitize_text(parsed.path or "/")

                existing = (await session.execute(
                    select(URL).where(URL.asset_id == asset.id, URL.url == clean_target_url)
                )).scalar_one_or_none()

                url_record = existing
                if not url_record:
                    url_record = URL(
                        asset_id=asset.id,
                        url=clean_target_url,
                        scheme=parsed.scheme,
                        host=host,
                        port=port_num,
                        path=clean_path,
                        status_code=status,
                        content_type=clean_ct,
                        title=clean_title,
                    )
                    session.add(url_record)
                    await session.flush()

                if status < 400 or status in (401, 403):
                    await ctx.emit(
                        "url.discovered",
                        f"Endpoint: {clean_target_url} [{status}]" + (f" — \"{clean_title}\"" if clean_title else ""),
                        url=clean_target_url,
                        status_code=status,
                        host=host,
                        title=clean_title,
                        asset_id=asset.id,
                        severity="info" if status < 400 else "warn",
                    )

                # Parameter Extraction (Query string & HTML forms)
                found_params = _extract_parameters_from_url(clean_target_url)
                if resp.text and status == 200:
                    found_params.extend(_extract_form_inputs(resp.text))

                for raw_param_name, loc in set(found_params):
                    param_name = sanitize_text(raw_param_name)
                    existing_param = (await session.execute(
                        select(Parameter).where(
                            Parameter.url_id == url_record.id,
                            Parameter.name == param_name,
                            Parameter.location == loc,
                        )
                    )).scalar_one_or_none()

                    if not existing_param:
                        session.add(Parameter(
                            url_id=url_record.id,
                            name=param_name,
                            location=loc,
                            type="string",
                            confidence=0.9,
                        ))
                        await ctx.emit(
                            "parameter.discovered",
                            f"Parameter [{loc}]: {param_name} detected on {clean_path}",
                            name=param_name,
                            location=loc,
                            url=clean_target_url,
                            asset_id=asset.id,
                            severity="info",
                        )

                # Shallow Link Crawling from HTML Body (max length check)
                if resp.text and len(resp.text) < 500_000 and status == 200:
                    for match in re.finditer(r'(?:href|src|action)=["\']([^"\'#\s>]+)["\']', resp.text, re.IGNORECASE):
                        raw_link = match.group(1)
                        if raw_link.startswith(("javascript:", "mailto:", "tel:", "data:")):
                            continue
                        full_link = urljoin(target_url, raw_link)
                        p_link = urlparse(full_link)
                        if p_link.scheme in ("http", "https") and p_link.hostname == host:
                            norm_link = full_link.rstrip("/")
                            if norm_link not in seen_urls and len(seen_urls) < settings.max_urls_per_scan:
                                seen_urls.add(norm_link)
                                # Add discovered link as URL record
                                existing_link = (await session.execute(
                                    select(URL).where(URL.asset_id == asset.id, URL.url == full_link)
                                )) .scalar_one_or_none()
                                if not existing_link:
                                    session.add(URL(
                                        asset_id=asset.id,
                                        url=full_link,
                                        scheme=p_link.scheme,
                                        host=host,
                                        port=p_link.port or (443 if p_link.scheme == "https" else 80),
                                        path=p_link.path or "/",
                                        status_code=None,
                                        content_type="",
                                    ))
                                    await ctx.emit(
                                        "url.discovered",
                                        f"Discovered Link: {full_link}",
                                        url=full_link,
                                        host=host,
                                        asset_id=asset.id,
                                        severity="info",
                                    )
                await session.commit()

    await asyncio.gather(*[probe_endpoint(u) for u in to_probe], return_exceptions=True)



async def run(ctx: ScanContext, db: AsyncSession, root_domain: str) -> None:
    """URL Discovery, Endpoint Crawling & Parameter Extraction."""
    if ctx.profile == "passive":
        return

    await ctx.emit("scan.web", f"Starting web endpoint & parameter discovery for {root_domain}", severity="info")

    assets = (await db.execute(
        select(Asset).where(
            Asset.scan_id == ctx.scan_id,
            Asset.asset_type.in_(["domain", "subdomain"]),
        )
    )).scalars().all()

    assets = sorted(assets, key=lambda a: a.depth)[: settings.max_web_hosts]

    for a in assets:
        await crawl_and_discover_asset(ctx, db, a, root_domain)