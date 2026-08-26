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
from app.core.db import AsyncSessionLocal
from app.core.sanitizer import sanitize_text
from app.models.models import Asset, Certificate, Port, Service, Technology, URL
from app.scanners.base import ScanContext
from app.services.results import result_service



logger = logging.getLogger("scanner.http")

TECH_SIGNATURES: List[Tuple[str, str, str, str]] = [
    # (Tech Name, Version Regex / Pattern, Category, Evidence Location)
    ("Nginx", r"nginx(?:/([\d.]+))?", "Web Server", "Server Header"),
    ("Apache HTTP Server", r"Apache(?:/([\d.]+))?", "Web Server", "Server Header"),
    ("Cloudflare", r"cloudflare|__cf_bm|_cfuvid|cf-ray", "CDN / WAF", "Server Header / Headers"),
    ("Pure 360 / PureWeb WAF", r"pure360|pure-360|pureweb|pure_firewall", "WAF", "Headers / Body"),
    ("Imperva / Incapsula WAF", r"incap_ses|_incap_|visid_incap|X-Iinfo", "WAF", "Headers / Cookies"),
    ("ModSecurity WAF", r"Mod_Security|mod_security|NOYB", "WAF", "Headers / Server"),
    ("F5 BIG-IP WAF / ADC", r"BigIP|BIGipServer|TS[a-zA-Z0-9]{8}", "WAF / ADC", "Headers / Cookies"),
    ("AWS WAF", r"awswaf|aws-waf|x-amzn-waf", "WAF", "Headers"),
    ("Fortinet FortiWeb", r"FORTIWAF|fortiweb", "WAF", "Cookies / Headers"),
    ("Akamai Edge / Kona", r"akamai|AkamaiGHost", "CDN / WAF", "Server Header"),
    ("Sucuri CloudProxy", r"Sucuri|X-Sucuri-ID", "WAF", "Headers"),
    ("DDoS-Guard", r"ddos-guard|ddos_guard", "WAF / Anti-DDoS", "Headers / Body"),
    ("LiteSpeed", r"LiteSpeed", "Web Server", "Server Header"),
    ("Microsoft IIS", r"Microsoft-IIS(?:/([\d.]+))?", "Web Server", "Server Header"),
    ("Caddy", r"Caddy", "Web Server", "Server Header"),
    ("Envoy", r"envoy", "Proxy", "Server Header"),
    ("OpenResty", r"openresty(?:/([\d.]+))?", "Web Server", "Server Header"),
    ("PHP", r"PHP/([\d.]+)|(?:X-Powered-By|Server):\s*PHP/([\d.]+)|PHP", "Language", "Headers"),
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
    ("Suspended / Inactive Site", r"this site is currently suspended|account suspended|cgi-sys/suspendedpage|this account has been suspended", "Hosting Status", "HTML Body"),
    ("Parked Domain", r"domain is parked|parkingcrew|sedoparking|domain expired", "Hosting Status", "HTML Body"),
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


_SHARED_CLIENT: httpx.AsyncClient | None = None
_SHARED_CLIENT_LOCK = asyncio.Lock()

async def get_shared_client() -> httpx.AsyncClient:
    """Get or create the global shared AsyncClient with connection pooling limits."""
    global _SHARED_CLIENT
    if _SHARED_CLIENT is None:
        async with _SHARED_CLIENT_LOCK:
            if _SHARED_CLIENT is None:
                # Use connection limits to avoid socket exhaustion and reuse connections (Keep-Alive)
                limits = httpx.Limits(max_keepalive_connections=50, max_connections=150, keepalive_expiry=30.0)
                _SHARED_CLIENT = httpx.AsyncClient(
                    limits=limits,
                    follow_redirects=False,
                    verify=False,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 (BugHunter/1.0)"}
                )
    return _SHARED_CLIENT

async def fetch_http(url: str, timeout: float = 8.0, max_bytes: int = 1500000) -> httpx.Response | None:
    """Non-blocking HTTP GET with connection reuse and response size limit to prevent memory exhaustion."""
    try:
        client = await get_shared_client()
        # Stream response to enforce size limit and prevent memory exhaustion
        async with client.stream("GET", url, timeout=timeout) as response:
            content_chunks = []
            bytes_read = 0
            async for chunk in response.aiter_bytes(chunk_size=16384):
                content_chunks.append(chunk)
                bytes_read += len(chunk)
                if bytes_read >= max_bytes:
                    break
            
            full_content = b"".join(content_chunks)
            # Build a response object
            mock_resp = httpx.Response(
                status_code=response.status_code,
                headers=response.headers,
                content=full_content,
                request=response.request
            )
            return mock_resp
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

    # Standard and Extended Web Endpoint Candidates
    candidate_endpoints = [("https", 443), ("http", 80)]
    if ctx.profile == "deep":
        candidate_endpoints.extend([
            ("https", 8443), ("http", 8080), ("http", 8000),
            ("https", 2083), ("https", 2087), ("http", 8888),
            ("http", 3000), ("http", 5000), ("https", 9443), ("https", 10443)
        ])

    for scheme, port_num in candidate_endpoints:
        port_suffix = f":{port_num}" if port_num not in (80, 443) else ""
        url = f"{scheme}://{host}{port_suffix}/"
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
                loc = f"{scheme}://{host}{port_suffix}{loc}"
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

        # Guarantee open Port & Service are persisted in database
        existing_port = (await db.execute(
            select(Port).where(
                Port.asset_id == asset.id,
                Port.port == port_num,
                Port.protocol == "tcp",
            )
        )).scalar_one_or_none()

        if not existing_port:
            new_port = Port(
                asset_id=asset.id,
                ip=asset.ip,
                port=port_num,
                protocol="tcp",
                state="open",
                service=scheme,
                banner=server_header or None,
            )
            db.add(new_port)
            await db.flush()
            port_record_id = new_port.id
        else:
            if server_header and not existing_port.banner:
                existing_port.banner = server_header
            if not existing_port.service or existing_port.service == "unknown":
                existing_port.service = scheme
            port_record_id = existing_port.id

        existing_svc = (await db.execute(
            select(Service).where(Service.asset_id == asset.id, Service.port_id == port_record_id)
        )).scalar_one_or_none()

        if not existing_svc:
            db.add(Service(
                asset_id=asset.id,
                port_id=port_record_id,
                name=scheme,
                protocol="tcp",
                tls_enabled=(scheme == "https"),
                banner=server_header or None,
                metadata_={"port": port_num, "server": server_header, "title": clean_title},
            ))

        await ctx.emit(
            "http.available",
            f"HTTP [{status}] {clean_url_str}" + (f" — \"{clean_title}\"" if clean_title else "") + f" ({latency_ms}ms)",
            url=clean_url_str,
            status_code=status,
            host=host,
            port=port_num,
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
                ver = next((g for g in m_hdr.groups() if g), None) if m_hdr.groups() else None
                detected_tech[tech_name] = {"version": ver, "category": category, "evidence": f"{location}: {m_hdr.group(0)}"}

            # Match against HTML body
            if resp.text and len(resp.text) < 1_000_000:
                m_body = re.search(pattern, resp.text, re.IGNORECASE)
                if m_body and tech_name not in detected_tech:
                    ver = next((g for g in m_body.groups() if g), None) if m_body.groups() else None
                    detected_tech[tech_name] = {"version": ver, "category": category, "evidence": f"HTML Body match"}

        # Specialized CMS & WordPress Intelligence (§75-78)
        if resp.text:
            from app.intelligence.cms import CmsDetector
            cms_res = CmsDetector.detect(resp.text, dict(resp.headers))
            if cms_res:
                cms_name = cms_res["cms"]
                detected_tech[cms_name] = {
                    "version": cms_res.get("version"),
                    "category": "CMS",
                    "evidence": f"CMS Detector: {cms_name}",
                }
                for plugin in cms_res.get("plugins", []):
                    detected_tech[f"WordPress Plugin: {plugin}"] = {
                        "version": None,
                        "category": "CMS Plugin",
                        "evidence": f"Plugin path /wp-content/plugins/{plugin}/",
                    }
                if cms_res.get("theme"):
                    detected_tech[f"WordPress Theme: {cms_res['theme']}"] = {
                        "version": None,
                        "category": "CMS Theme",
                        "evidence": f"Theme path /wp-content/themes/{cms_res['theme']}/",
                    }

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
            async with AsyncSessionLocal() as session:
                await probe_asset(ctx, session, a, root_domain)

    await asyncio.gather(*[probe_with_sem(a) for a in assets], return_exceptions=True)