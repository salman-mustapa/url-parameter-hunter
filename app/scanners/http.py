from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import ssl
import time
from datetime import datetime, timezone
from typing import Any, List, Set, Tuple
from urllib.parse import urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.sanitizer import sanitize_text
from app.models.models import Asset, Certificate, Technology, URL
from app.scanners.base import ScanContext
from app.services.results import result_service


logger = logging.getLogger("scanner.http")

TECH_SIGNATURES: List[Tuple[str, str, str, str]] = [
    # (Tech Name, Version Regex / Pattern, Category, Evidence Location)
    ("Nginx", r"nginx(?:/([\d.]+))?", "Web Server", "Server Header"),
    ("Apache HTTP Server", r"Apache(?:/([\d.]+))?", "Web Server", "Server Header"),
    ("Cloudflare", r"cloudflare", "CDN / WAF", "Server Header / Headers"),
    ("LiteSpeed", r"LiteSpeed", "Web Server", "Server Header"),
    ("Microsoft IIS", r"Microsoft-IIS(?:/([\d.]+))?", "Web Server", "Server Header"),
    ("Caddy", r"Caddy", "Web Server", "Server Header"),
    ("Envoy", r"envoy", "Proxy", "Server Header"),
    ("OpenResty", r"openresty(?:/([\d.]+))?", "Web Server", "Server Header"),
    ("PHP", r"PHP(?:/([\d.]+))?|X-Powered-By: PHP", "Language", "Headers"),
    ("WordPress", r"wp-content|wp-includes|generator[\"']\s+content=[\"']WordPress\s*([\d.]*)", "CMS", "HTML Body"),
    ("Laravel", r"laravel|X-Powered-By:.*Laravel", "Framework", "Headers / Cookies"),
    ("Django", r"csrftoken|django", "Framework", "Cookies / HTML"),
    ("Ruby on Rails", r"_rails_|X-CSRF-Token|phusion_passenger", "Framework", "Headers / Cookies"),
    ("Express.js / Node.js", r"X-Powered-By: Express|node\.js", "Framework", "Headers"),
    ("Spring Boot", r"Whitelabel Error Page|spring|X-Application-Context", "Framework", "Headers / Body"),
    ("ASP.NET", r"ASP\.NET|X-AspNet-Version", "Framework", "Headers"),
    ("Next.js", r"__NEXT_DATA__|_next/static", "Frontend Framework", "HTML Body"),
    ("Nuxt.js", r"__NUXT__|nuxt", "Frontend Framework", "HTML Body"),
    ("React", r"react\.production\.min\.js|__REACT_DEVTOOLS_GLOBAL_HOOK__|data-reactroot", "Frontend Library", "HTML Body"),
    ("Vue.js", r"vue\.runtime\.min\.js|data-v-[a-f0-9]+|v-cloak", "Frontend Framework", "HTML Body"),
    ("Angular", r"ng-version=[\"']([^\"']+)[\"']|ng-app", "Frontend Framework", "HTML Body"),
    ("Tailwind CSS", r"tailwind|font-sans|bg-slate-", "CSS Framework", "HTML Body"),
    ("Bootstrap", r"bootstrap(?:\.min)?\.css|data-bs-toggle", "CSS Framework", "HTML Body"),
    ("jQuery", r"jquery(?:-([\d.]+))?(?:\.min)?\.js", "JavaScript Library", "HTML Body"),
    ("Google Analytics / GTM", r"gtag\(|googletagmanager\.com", "Analytics", "HTML Body"),
    ("Fastly", r"Fastly|X-Fastly", "CDN", "Headers"),
    ("Amazon S3 / CloudFront", r"AmazonS3|CloudFront|X-Amz-", "Cloud CDN", "Headers"),
]

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE


async def extract_tls_cert(host: str, port: int = 443) -> dict | None:
    """Extract detailed TLS certificate metadata."""
    loop = asyncio.get_running_loop()

    def do_ssl():
        import socket
        import cryptography.x509 as x509

        try:
            raw_sock = socket.create_connection((host, port), timeout=4.0)
            with SSL_CTX.wrap_socket(raw_sock, server_hostname=host) as conn:
                der = conn.getpeercert(binary_form=True)
                if not der:
                    return None
                cert = x509.load_der_x509_certificate(der)
                fp = hashlib.sha256(der).hexdigest()

                san_list = []
                try:
                    ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    san_list = [n.value for n in ext.value if isinstance(n, x509.DNSName)]
                except Exception:
                    pass

                sig_name = getattr(cert.signature_algorithm_oid, "_name", "unknown")

                return {
                    "fingerprint_sha256": fp,
                    "subject_cn": cert.subject.rfc4514_string(),
                    "issuer_cn": cert.issuer.rfc4514_string(),
                    "not_before": cert.not_valid_before_utc,
                    "not_after": cert.not_valid_after_utc,
                    "san_dns": san_list,
                    "signature_algorithm": sig_name,
                }
        except Exception:
            return None

    try:
        return await asyncio.wait_for(loop.run_in_executor(None, do_ssl), timeout=6.0)
    except Exception:
        return None


async def fetch_http(url: str, timeout: float = 8.0) -> httpx.Response | None:
    """Non-blocking HTTP GET with security boundaries."""
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 (BugHunter/1.0)"}
        ) as client:
            return await client.get(url)
    except Exception:
        return None


def extract_title(html: str) -> str | None:
    if not html:
        return None
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if m:
        return re.sub(r"\s+", " ", m.group(1)).strip()[:180]
    return None


async def probe_asset(ctx: ScanContext, db: AsyncSession, asset: Asset, root_domain: str) -> None:
    """HTTP/HTTPS probe for an individual asset."""
    host = asset.hostname
    if not host or not ctx.scope.host_allowed(host):
        return

    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        t0 = time.time()
        resp = await fetch_http(url, timeout=settings.http_timeout_seconds)
        latency_ms = int((time.time() - t0) * 1000)

        if resp is None:
            continue

        status = resp.status_code
        title = extract_title(resp.text) if resp.text else None
        content_type = (resp.headers.get("content-type") or "").split(";")[0].strip()[:100]
        server_header = resp.headers.get("server", "")

        # Follow in-scope redirect check
        if resp.is_redirect:
            loc = resp.headers.get("location", "")
            if loc.startswith("/"):
                loc = f"{scheme}://{host}{loc}"
            if loc and not ctx.scope.url_allowed(loc):
                await ctx.emit(
                    "scope.denied",
                    f"Redirect out of authorized scope: {loc} (from {url})",
                    url=loc,
                    host=host,
                    severity="warn",
                )

        # Upsert URL Asset
        parsed = urlparse(url)

        port_num = parsed.port or (443 if scheme == "https" else 80)
        clean_url_str = sanitize_text(url)
        clean_title = sanitize_text(title)
        clean_ct = sanitize_text(content_type)

        existing_url = (await db.execute(
            select(URL).where(URL.asset_id == asset.id, URL.url == clean_url_str)
        )).scalar_one_or_none()

        if not existing_url:
            db.add(URL(
                asset_id=asset.id,
                url=clean_url_str,
                scheme=scheme,
                host=host,
                port=port_num,
                path=sanitize_text(parsed.path or "/"),
                status_code=status,
                content_type=clean_ct,
                title=clean_title,
            ))

        await ctx.emit(
            "http.available",
            f"HTTP [{status}] {clean_url_str}" + (f" — \"{clean_title}\"" if clean_title else "") + f" ({latency_ms}ms)",
            url=clean_url_str,
            status_code=status,
            host=host,
            title=clean_title,
            content_type=clean_ct,
            latency_ms=latency_ms,
            asset_id=asset.id,
            severity="info" if status < 400 else "warn",
        )


        # TLS Certificate Capture for HTTPS
        if scheme == "https":
            cert_info = await extract_tls_cert(host, port_num)
            if cert_info:
                existing_cert = (await db.execute(
                    select(Certificate).where(
                        Certificate.asset_id == asset.id,
                        Certificate.fingerprint_sha256 == cert_info["fingerprint_sha256"],
                    )
                )).scalar_one_or_none()

                if not existing_cert:
                    db.add(Certificate(asset_id=asset.id, hostname=host, **cert_info))
                    await ctx.emit(
                        "cert.captured",
                        f"TLS Certificate: {host} (Issued to: {cert_info.get('subject_cn', 'N/A')})",
                        hostname=host,
                        subject=cert_info.get("subject_cn"),
                        issuer=cert_info.get("issuer_cn"),
                        san_dns=cert_info.get("san_dns", []),
                        asset_id=asset.id,
                        severity="info",
                    )

        # Security Headers Evaluation (Recorded as Observation, not auto-vulnerability per §18)
        missing_sec_headers = []
        hdr_lower = {k.lower(): v for k, v in resp.headers.items()}
        for expected_hdr in (
            "strict-transport-security",
            "x-frame-options",
            "x-content-type-options",
            "content-security-policy",
            "referrer-policy",
        ):
            if expected_hdr not in hdr_lower:
                missing_sec_headers.append(expected_hdr)

        if missing_sec_headers:
            await result_service.upsert_observation(
                db,
                scan_id=ctx.scan_id,
                asset_id=asset.id,
                observation_type="security_headers",
                title=f"Missing security headers ({len(missing_sec_headers)})",
                evidence={"url": url, "missing": missing_sec_headers, "present": list(hdr_lower.keys())},
                confidence=0.9,
            )

        # Technology Detection from Headers & HTML
        headers_combined = " ".join(f"{k}: {v}" for k, v in resp.headers.items())
        detected_tech: dict[str, dict[str, Any]] = {}

        for tech_name, pattern, category, location in TECH_SIGNATURES:
            # Match against headers
            m_hdr = re.search(pattern, headers_combined, re.IGNORECASE)
            if m_hdr:
                ver = m_hdr.group(1) if m_hdr.groups() and m_hdr.group(1) else None
                detected_tech[tech_name] = {"version": ver, "category": category, "evidence": f"{location}: {m_hdr.group(0)}"}

            # Match against HTML body
            if resp.text and len(resp.text) < 1_000_000:
                m_body = re.search(pattern, resp.text, re.IGNORECASE)
                if m_body and tech_name not in detected_tech:
                    ver = m_body.group(1) if m_body.groups() and m_body.group(1) else None
                    detected_tech[tech_name] = {"version": ver, "category": category, "evidence": f"HTML Body match"}

        for tech_name, t_meta in detected_tech.items():
            existing_tech = (await db.execute(
                select(Technology).where(
                    Technology.asset_id == asset.id,
                    Technology.name == tech_name,
                    Technology.version == t_meta["version"],
                )
            )).scalar_one_or_none()

            if not existing_tech:
                db.add(Technology(
                    asset_id=asset.id,
                    name=tech_name,
                    version=t_meta["version"],
                    confidence=0.85,
                    evidence=t_meta["evidence"],
                ))
                await ctx.emit(
                    "technology.detected",
                    f"Tech Detected on {host}: {tech_name}" + (f" v{t_meta['version']}" if t_meta["version"] else "") + f" [{t_meta['category']}]",
                    hostname=host,
                    name=tech_name,
                    version=t_meta["version"],
                    category=t_meta["category"],
                    asset_id=asset.id,
                    severity="info",
                )

        await db.commit()


async def run(ctx: ScanContext, db: AsyncSession, root_domain: str) -> None:
    """HTTP/HTTPS Probing, TLS Inspection & Technology Detection."""
    await ctx.emit("scan.http", f"Starting HTTP probing and tech fingerprinting for {root_domain}", severity="info")

    assets = (await db.execute(
        select(Asset).where(
            Asset.scan_id == ctx.scan_id,
            Asset.asset_type.in_(["domain", "subdomain"]),
        )
    )).scalars().all()

    # Sort shallow depth first and cap to configured budget
    assets = sorted(assets, key=lambda a: a.depth)[: settings.max_http_hosts]
    sem = asyncio.Semaphore(settings.max_concurrent_hosts)

    async def probe_with_sem(a: Asset):
        async with sem:
            await ctx.rate_limiter.wait()
            await probe_asset(ctx, db, a, root_domain)

    await asyncio.gather(*[probe_with_sem(a) for a in assets], return_exceptions=True)