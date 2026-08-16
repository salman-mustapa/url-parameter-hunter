from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import Asset, URL
from app.scanners.base import ScanContext
from app.services.results import result_service

logger = logging.getLogger("scanner.security")

# Simple, non-destructive checks producing Findings + Observations
SECURITY_CHECKS = [
    {
        "type": "info_exposure",
        "title": "Sensitive file exposure",
        "severity": "MEDIUM",
        "match": [".env", "config.php", ".git/HEAD", "backup", "swagger"],
        "desc": "Endpoint yang berpotensi mengekspos informasi sensitif terbuka.",
    },
    {
        "type": "info_exposure",
        "title": "Directory listing possible",
        "severity": "LOW",
        "match": ["/error", "/status", "/server-status"],
        "desc": "Endpoint info server terdeteksi.",
    },
]


async def run(ctx: ScanContext, db: AsyncSession, root_domain: str) -> None:
    await ctx.emit("scan.security", f"Security analysis for {root_domain}")

    urls = (await db.execute(
        select(URL).where(URL.asset_id.in_(
            select(Asset.id).where(Asset.scan_id == ctx.scan_id)
        ))
    )).scalars().all()

    for url in urls:
        for check in SECURITY_CHECKS:
            if any(k in url.url for k in check["match"]):
                await result_service.upsert_finding(
                    db, scan_id=ctx.scan_id, asset_id=url.asset_id,
                    finding_type=check["type"], title=check["title"],
                    severity=check["severity"], confidence=0.7,
                    description=check["desc"],
                    evidence={"url": url.url, "status_code": url.status_code},
                )
                await ctx.emit("finding.created",
                               f"{check['severity']}: {check['title']} — {url.url}",
                               severity=check["severity"], url=url.url,
                               asset_id=url.asset_id, confidence=0.7)

    await db.commit()