from __future__ import annotations

import asyncio
import logging
import re
import ssl
from typing import Any
from urllib.parse import urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.models import Asset, Certificate, URL
from app.scanners.base import ScanContext
from app.services.results import result_service

logger = logging.getLogger("scanner.http")

TECH_PATTERNS = [
    ("nginx", r"nginx(?:/([\d.]+))?", {"Server header"}),
    ("apache", r"Apache(?:/([\d.]+))?", {"Server header"}),
    ("cloudflare", r"cloudflare", {"Server header"}),
    ("wordpress", r"wp-content|wp-includes", {"HTML body"}),
    ("laravel/php", r"laravel|X-Powered-By: PHP", {"Header/body"}),
    ("react", r"__NEXT_DATA__|react", {"HTML body"}),
    ("next.js", r"__NEXT_DATA__|_next/static", {"HTML body"}),
    ("express/node", r"X-Powered-By: Express", {"Header"}),
    ("tomcat", r"Apache Tomcat|tomcat", {"Header/body"}),
    ("spring", r"spring|Spring", {"Header/body"}),
]

SSL_CTX = ssl.create_default_context()


async def get_cert(host: str, port: int = 443) -> dict | None:
    try:
        conn = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(None, lambda: SSL_CTX.wrap_socket(
                __import__("socket").create_connection((host, port), timeout=5), server_hostname=host)),
            timeout=8,
        )
        der = conn.getpeercert(binary_form=True)
        conn.close()
        if not der:
            return None
        import hashlib

        import cryptography.x509 as x509
        from cryptography.hazmat.primitives import hashes
        cert = x509.load_der_x509_certificate(der)
        fp = hashlib.sha256(der).hexdigest()
        return {
            "fingerprint_sha256": fp,
            "subject_cn": cert.subject.rfc4514_string(),
            "issuer_cn": cert.issuer.rfc4514_string(),
            "not_before": cert.not_valid_before_utc,
            "not_after": cert.not_valid_after_utc,
            "san_dns": [n.value for n in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value if isinstance(n, x509.DNSName)],
            "signature_algorithm": cert.signature_algorithm_oid._name,
        }
    except Exception:
        return None


async def fetch(url: str, timeout: float = 10.0, headers: dict | None = None) -> httpx.Response | None:
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, verify=False,
                                     headers=headers or {"User-Agent": "Mozilla/5.0 (BugHunter/0.4)"}) as client:
            resp = await client.get(url)
            return resp
    except Exception:
        return None


async def probe_host(ctx: ScanContext, db: AsyncSession, host: str, root_domain: str) -> None:
    """HTTP/HTTPS probe for a hostname; records URL assets + technologies."""
    if not ctx.scope.host_allowed(host):
        return
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        resp = await fetch(url, timeout=settings.http_timeout_seconds)
        if resp is None:
            continue

        # follow redirects manually — but only within scope
        final_url = url
        status = resp.status_code
        if resp.is_redirect:
            loc = resp.headers.get("location", "")
            if loc.startswith("/"):
                loc = f"{scheme}://{host}{loc}"
            if ctx.scope.url_allowed(loc) if loc else False:
                final_url = loc
                # optionally fetch final
            else:
                await ctx.emit("scope.denied", f"Redirect out of scope: {loc}",
                               url=loc, host=host, severity="warn")
                return

        asset = (await db.execute(
            select(Asset).where(Asset.scan_id == ctx.scan_id, Asset.hostname == host)
        )).scalar_one_or_none()
        if not asset:
            continue

        existing = (await db.execute(
            select(URL).where(URL.asset_id == asset.id, URL.url == url)
        )).scalar_one_or_none()
        if not existing:
            parsed = urlparse(url)
            db.add(URL(
                asset_id=asset.id, url=url, scheme=parsed.scheme, host=host,
                port=parsed.port or (443 if scheme == "https" else 80),
                path=parsed.path or "/", status_code=status,
                content_type=resp.headers.get("content-type", "")[:200],
                title=extract_title(resp.text) if resp.text else None,
            ))
        await ctx.emit("http.available", f"{url} [{status}]", url=url, status_code=status,
                       host=host, asset_id=asset.id)

        # TLS certificate capture (https only)
        if scheme == "https":
            cert_info = await get_cert(host, parsed.port or 443)
            if cert_info:
                existing_cert = (await db.execute(
                    select(Certificate).where(
                        Certificate.asset_id == asset.id,
                        Certificate.fingerprint_sha256 == cert_info["fingerprint_sha256"],
                    )
                )).scalar_one_or_none()
                if not existing_cert:
                    db.add(Certificate(asset_id=asset.id, hostname=host, **cert_info))
                    await ctx.emit("cert.captured", f"TLS cert captured for {host}",
                                   hostname=host, subject=cert_info["subject_cn"],
                                   issuer=cert_info["issuer_cn"], asset_id=asset.id)

        # HTTP security header observations (non-finding)
        missing_headers = []
        for hdr in ("strict-transport-security", "x-frame-options", "x-content-type-options", "content-security-policy", "referrer-policy"):
            if hdr not in {k.lower() for k in resp.headers.keys()}:
                missing_headers.append(hdr)
        if missing_headers:
            await result_service.upsert_observation(
                db, scan_id=ctx.scan_id, asset_id=asset.id, observation_type="http_headers",
                title="Missing security headers",
                evidence={"url": url, "missing": missing_headers}, confidence=0.8,
            )
            await ctx.emit("observation.recorded",
                           f"Observation: missing security headers on {host}",
                           hostname=host, missing=missing_headers, asset_id=asset.id)

        # technology detection from headers
        techs_detected: list[str] = []
        header_blob = " ".join(f"{k}: {v}" for k, v in resp.headers.items()).lower()
        for name, pattern, _ in TECH_PATTERNS:
            if re.search(pattern, header_blob, re.IGNORECASE):
                techs_detected.append(name)
        if resp.text:
            for name, pattern, _ in TECH_PATTERNS:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    techs_detected.append(name)

        from app.models.models import Technology
        for tech in set(techs_detected):
            existing_tech = (await db.execute(
                select(Technology).where(Technology.asset_id == asset.id, Technology.name == tech)
            )).scalar_one_or_none()
            if not existing_tech:
                db.add(Technology(asset_id=asset.id, name=tech, version=None, confidence=0.7,
                                  evidence="HTTP probe"))
            await ctx.emit("technology.detected", f"Detected {tech} on {host}",
                           hostname=host, name=tech, asset_id=asset.id)
        await db.commit()


def extract_title(html: str) -> str | None:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if m:
        return m.group(1).strip()[:200]
    return None


async def run(ctx: ScanContext, db: AsyncSession, root_domain: str) -> None:
    await ctx.emit("scan.http", f"HTTP probing for {root_domain}")
    assets = (await db.execute(
        select(Asset).where(Asset.scan_id == ctx.scan_id, Asset.asset_type.in_(["domain", "subdomain"]))
    )).scalars().all()
    # cap probe hosts: prefer root + shallow depth
    assets = sorted(assets, key=lambda a: a.depth)[: settings.max_http_hosts]
    hosts = [a.hostname for a in assets if a.hostname]
    await asyncio.gather(*[probe_host(ctx, db, h, root_domain) for h in hosts], return_exceptions=True)