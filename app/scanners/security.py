from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import Asset, Certificate, Port, Technology, URL
from app.scanners.base import ScanContext
from app.services.results import result_service

logger = logging.getLogger("scanner.security")

# Non-destructive security checks. Each produces Finding (with severity) or Observation.
URL_MATCH_CHECKS = [
    {
        "finding_type": "info_exposure",
        "title": "Sensitive file exposure",
        "severity": "MEDIUM",
        "match": [".env", "config.php", ".git/HEAD", "backup", "swagger", "phpinfo.php", "info.php"],
        "desc": "Endpoint yang berpotensi mengekspos informasi sensitif terbuka.",
    },
    {
        "finding_type": "info_exposure",
        "title": "Admin panel exposure",
        "severity": "MEDIUM",
        "match": ["/admin", "/administrator", "/wp-admin", "/panel"],
        "desc": "Panel administrasi terdeteksi — permukaan autentikasi publik.",
    },
    {
        "finding_type": "info_exposure",
        "title": "API documentation exposure",
        "severity": "LOW",
        "match": ["/swagger", "/api/docs", "/redoc", "/graphql", "/openapi"],
        "desc": "Dokumentasi API publik terpapar.",
    },
    {
        "finding_type": "info_exposure",
        "title": "Potential directory listing / info endpoint",
        "severity": "LOW",
        "match": ["/error", "/status", "/server-status", "/debug"],
        "desc": "Endpoint info server terdeteksi.",
    },
]

HEADER_CHECKS = [
    ("X-Frame-Options", "security_misconfiguration", "Clickjacking protection missing", "MEDIUM",
     "Header X-Frame-Options tidak ada di response."),
    ("Content-Security-Policy", "security_misconfiguration", "CSP header missing", "LOW",
     "Header Content-Security-Policy tidak ada."),
    ("Strict-Transport-Security", "security_misconfiguration", "HSTS header missing", "LOW",
     "Header Strict-Transport-Security tidak ada pada HTTPS."),
    ("X-Content-Type-Options", "security_misconfiguration", "MIME sniffing protection missing", "LOW",
     "Header X-Content-Type-Options tidak ada."),
]

MISSING_TLS_CHECKS = [
    ("certificate_expired", "TLS certificate expired", "HIGH"),
    ("certificate_expiring_soon", "TLS certificate expiring soon", "MEDIUM"),
]


async def run(ctx: ScanContext, db: AsyncSession, root_domain: str) -> None:
    await ctx.emit("scan.security", f"Security analysis for {root_domain}")

    asset_ids = select(Asset.id).where(Asset.scan_id == ctx.scan_id)

    # --- URL-based checks ---
    urls = (await db.execute(
        select(URL).where(URL.asset_id.in_(asset_ids))
    )).scalars().all()

    for url_obj in urls:
        for check in URL_MATCH_CHECKS:
            if any(k in url_obj.url for k in check["match"]):
                finding = await result_service.upsert_finding(
                    db, scan_id=ctx.scan_id, asset_id=url_obj.asset_id,
                    finding_type=check["finding_type"], title=check["title"],
                    severity=check["severity"], confidence=0.7,
                    description=check["desc"],
                    evidence={"url": url_obj.url, "status_code": url_obj.status_code},
                )
                if finding:
                    await ctx.emit("finding.created",
                                   f"{check['severity']}: {check['title']} — {url_obj.url}",
                                   severity=check["severity"], url=url_obj.url,
                                   asset_id=url_obj.asset_id, confidence=0.7)

    # --- Header-based checks on probed root URLs ---
    root_urls = (await db.execute(
        select(URL).where(URL.asset_id.in_(asset_ids), URL.path.in_(["/", "/index.html", ""]))
    )).scalars().all()
    checked_hosts: set[str] = set()
    for url_obj in root_urls:
        if url_obj.host in checked_hosts:
            continue
        checked_hosts.add(url_obj.host)
        # headers already captured as observations in http scanner; skip duplicate findings here

    # --- TLS certificate checks ---
    certs = (await db.execute(
        select(Certificate).where(Certificate.asset_id.in_(asset_ids))
    )).scalars().all()
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    for cert in certs:
        if cert.not_after and cert.not_after < now:
            finding = await result_service.upsert_finding(
                db, scan_id=ctx.scan_id, asset_id=cert.asset_id,
                finding_type="tls", title="TLS certificate expired",
                severity="HIGH", confidence=0.95,
                description=f"Certificate untuk {cert.hostname} sudah kedaluwarsa sejak {cert.not_after.isoformat()}.",
                evidence={"hostname": cert.hostname, "not_after": cert.not_after.isoformat(),
                          "fingerprint": cert.fingerprint_sha256},
            )
            if finding:
                await ctx.emit("finding.created", f"HIGH: TLS certificate expired — {cert.hostname}",
                               severity="HIGH", hostname=cert.hostname, asset_id=cert.asset_id, confidence=0.95)
        elif cert.not_after and (cert.not_after - now).days < 30:
            finding = await result_service.upsert_finding(
                db, scan_id=ctx.scan_id, asset_id=cert.asset_id,
                finding_type="tls", title="TLS certificate expiring soon",
                severity="MEDIUM", confidence=0.8,
                description=f"Certificate untuk {cert.hostname} akan kedaluwarsa dalam {(cert.not_after - now).days} hari.",
                evidence={"hostname": cert.hostname, "not_after": cert.not_after.isoformat()},
            )
            if finding:
                await ctx.emit("finding.created", f"MEDIUM: TLS certificate expiring soon — {cert.hostname}",
                               severity="MEDIUM", hostname=cert.hostname, asset_id=cert.asset_id, confidence=0.8)

    await db.commit()