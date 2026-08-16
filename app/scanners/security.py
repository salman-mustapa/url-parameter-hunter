from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import Asset, Certificate, Finding, URL
from app.scanners.base import ScanContext
from app.services.results import result_service

logger = logging.getLogger("scanner.security")

SENSITIVE_PATH_PATTERNS = [
    {
        "pattern": r"/\.env(?:\.local|\.prod|\.bak)?$",
        "finding_type": "info_exposure",
        "title": "Environment Configuration File Exposed (.env)",
        "severity": "HIGH",
        "desc": "File konfigurasi .env terbuka ke publik, berpotensi mengekspos credential basis data, API secret, dan token aplikasi.",
        "valid_statuses": [200],
    },
    {
        "pattern": r"/\.git/(?:HEAD|config|index)",
        "finding_type": "info_exposure",
        "title": "Git Repository Metadata Exposed (.git)",
        "severity": "HIGH",
        "desc": "Direktori .git terbuka untuk diunduh publik, memungkinkan rekonstruksi source code dan riwayat commit aplikasi.",
        "valid_statuses": [200],
    },
    {
        "pattern": r"/phpinfo\.php|/info\.php",
        "finding_type": "info_exposure",
        "title": "PHP Info Diagnostic Page Exposed",
        "severity": "MEDIUM",
        "desc": "Halaman phpinfo() menampilkan detail lengkap arsitektur server, modul PHP terpasang, environment variables, dan jalur sistem file.",
        "valid_statuses": [200],
    },
    {
        "pattern": r"/backup(?:\.sql|\.zip|\.tar\.gz|\.bak)",
        "finding_type": "info_exposure",
        "title": "Database / Application Backup Archive Exposed",
        "severity": "HIGH",
        "desc": "File arsip cadangan (backup) terdeteksi dapat diakses publik, berpotensi memuat database dump atau source code lengkap.",
        "valid_statuses": [200],
    },
    {
        "pattern": r"/swagger-ui(?:\.html)?|/swagger\.json|/openapi\.json|/api/docs|/redoc",
        "finding_type": "info_exposure",
        "title": "Interactive API Documentation Exposed",
        "severity": "LOW",
        "desc": "Dokumentasi API interaktif terbuka publik, mempermudah pemetaan seluruh endpoint, model parameter, dan metode autentikasi backend.",
        "valid_statuses": [200],
    },
    {
        "pattern": r"/admin|/administrator|/wp-admin|/cpanel|/phpmyadmin",
        "finding_type": "auth_surface",
        "title": "Public Administrative Login Surface Detected",
        "severity": "LOW",
        "desc": "Portal administrasi terdeteksi di internet publik. Disarankan menerapkan pembatasan IP (whitelisting), MFA, atau VPN gateway.",
        "valid_statuses": [200, 401, 403],
    },
    {
        "pattern": r"/server-status|/actuator(?:/env|/health)?|/metrics",
        "finding_type": "info_exposure",
        "title": "Application Metrics & Diagnostic Endpoint Exposed",
        "severity": "MEDIUM",
        "desc": "Endpoint telemetri dan status server internal terbuka, mengekspos metrik sistem, daftar rute, atau status kesehatan server.",
        "valid_statuses": [200],
    },
]


async def run(ctx: ScanContext, db: AsyncSession, root_domain: str) -> None:
    """Non-destructive Security Analysis & Finding Engine."""
    if ctx.profile == "passive":
        return

    await ctx.emit("scan.security", f"Starting non-destructive security analysis for {root_domain}", severity="info")

    asset_ids_query = select(Asset.id).where(Asset.scan_id == ctx.scan_id)

    # 1. URL Path & Response Analysis
    urls = (await db.execute(
        select(URL).where(URL.asset_id.in_(asset_ids_query))
    )).scalars().all()

    import re
    for u in urls:
        if not u.status_code:
            continue

        for rule in SENSITIVE_PATH_PATTERNS:
            if re.search(rule["pattern"], u.url, re.IGNORECASE):
                if u.status_code in rule["valid_statuses"]:
                    finding = await result_service.upsert_finding(
                        db,
                        scan_id=ctx.scan_id,
                        asset_id=u.asset_id,
                        finding_type=rule["finding_type"],
                        title=rule["title"],
                        severity=rule["severity"],
                        confidence=0.90 if u.status_code == 200 else 0.70,
                        description=rule["desc"],
                        evidence={
                            "url": u.url,
                            "status_code": u.status_code,
                            "content_type": u.content_type,
                            "title": u.title,
                        },
                    )
                    if finding:
                        await ctx.emit(
                            "finding.created",
                            f"[{rule['severity']}] {rule['title']} on {u.url} (Status: {u.status_code})",
                            finding_id=finding.id,
                            title=rule["title"],
                            severity=rule["severity"],
                            url=u.url,
                            asset_id=u.asset_id,
                            confidence=0.90,
                        )

    # 2. TLS Certificate Validity Checks
    certs = (await db.execute(
        select(Certificate).where(Certificate.asset_id.in_(asset_ids_query))
    )).scalars().all()

    now = datetime.now(timezone.utc)
    for cert in certs:
        if not cert.not_after:
            continue

        # Expired TLS Certificate
        if cert.not_after < now:
            finding = await result_service.upsert_finding(
                db,
                scan_id=ctx.scan_id,
                asset_id=cert.asset_id,
                finding_type="tls_expired",
                title=f"Expired TLS Certificate for {cert.hostname}",
                severity="HIGH",
                confidence=0.98,
                description=f"Sertifikat SSL/TLS untuk host {cert.hostname} telah kedaluwarsa pada {cert.not_after.strftime('%d %b %Y %H:%M:%S UTC')}.",
                evidence={
                    "hostname": cert.hostname,
                    "expired_at": cert.not_after.isoformat(),
                    "fingerprint_sha256": cert.fingerprint_sha256,
                    "issuer": cert.issuer_cn,
                },
            )
            if finding:
                await ctx.emit(
                    "finding.created",
                    f"[HIGH] Expired TLS Certificate detected on {cert.hostname}",
                    finding_id=finding.id,
                    title="Expired TLS Certificate",
                    severity="HIGH",
                    hostname=cert.hostname,
                    asset_id=cert.asset_id,
                    confidence=0.98,
                )

        # Expiring Soon (< 21 days)
        elif (cert.not_after - now).days < 21:
            days_left = (cert.not_after - now).days
            finding = await result_service.upsert_finding(
                db,
                scan_id=ctx.scan_id,
                asset_id=cert.asset_id,
                finding_type="tls_expiring_soon",
                title=f"TLS Certificate Expiring Soon for {cert.hostname} ({days_left} days)",
                severity="MEDIUM",
                confidence=0.95,
                description=f"Sertifikat SSL/TLS untuk host {cert.hostname} akan kedaluwarsa dalam {days_left} hari ({cert.not_after.strftime('%d %b %Y')}).",
                evidence={
                    "hostname": cert.hostname,
                    "expires_at": cert.not_after.isoformat(),
                    "days_remaining": days_left,
                    "fingerprint_sha256": cert.fingerprint_sha256,
                },
            )
            if finding:
                await ctx.emit(
                    "finding.created",
                    f"[MEDIUM] TLS Certificate for {cert.hostname} expiring in {days_left} days",
                    finding_id=finding.id,
                    title="TLS Certificate Expiring Soon",
                    severity="MEDIUM",
                    hostname=cert.hostname,
                    asset_id=cert.asset_id,
                    confidence=0.95,
                )

    await db.commit()