"""Optional real browser captures. Missing browser support never produces fake screenshots."""
from __future__ import annotations

import asyncio
import hashlib
import io
import json
import logging
import socket
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit

from PIL import Image
from sqlalchemy import select

from app.core.config import SCREENSHOTS_DIR, settings
from app.core.db import AsyncSessionLocal
from app.core.paths import contained_path
from app.models.models import Asset, Screenshot

logger = logging.getLogger("scanner.screenshot")


class ScreenshotEngine:
    _slots = asyncio.Semaphore(max(1, settings.max_browser_captures))

    @staticmethod
    async def _public_address(url, scope):
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not scope.url_allowed(url):
            raise ValueError("Capture URL is outside authorized scope")
        addresses = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(
            parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM), 5)
        import ipaddress
        ips = {entry[4][0] for entry in addresses}
        if not ips or any(not ipaddress.ip_address(ip).is_global or not scope.ip_allowed(ip) for ip in ips):
            raise ValueError("Browser capture requires a public, scope-allowed IP")
        return sorted(ips)[0]

    @classmethod
    async def _capture_browser(cls, target_url, ctx):
        from playwright.async_api import async_playwright
        ip = await cls._public_address(target_url, ctx.scope)
        host = urlsplit(target_url).hostname
        pinned_ip = f"[{ip}]" if ":" in ip else ip
        blocked, requests = [], 0
        async with async_playwright() as runtime:
            browser = await runtime.chromium.launch(
                headless=True, chromium_sandbox=True,
                args=[f"--host-resolver-rules=MAP {host} {pinned_ip}, MAP * ~NOTFOUND",
                      "--disable-quic", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"])
            try:
                context = await browser.new_context(viewport={"width": 1280, "height": 720},
                    accept_downloads=False, service_workers="block", java_script_enabled=True)

                async def guard(route):
                    nonlocal requests
                    request = route.request
                    parsed = urlsplit(request.url)
                    requests += 1
                    allowed = (requests <= 80 and parsed.hostname == host and parsed.scheme in {"http", "https"}
                               and request.method in {"GET", "HEAD"} and ctx.scope.url_allowed(request.url))
                    if not allowed:
                        if len(blocked) < 20:
                            blocked.append(request.url[:300])
                        await route.abort()
                        return
                    await ctx.rate_limiter.wait()
                    await route.continue_()

                await context.route("**/*", guard)
                # Prevent background sockets; this capture is a bounded page observation.
                async def close_socket(ws):
                    await ws.close()
                await context.route_web_socket("**/*", close_socket)
                page = await context.new_page()
                response = await page.goto(target_url, wait_until="domcontentloaded", timeout=15000)
                if not response or not ctx.scope.url_allowed(page.url):
                    raise ValueError("Navigation did not produce an in-scope response")
                image_bytes = await page.screenshot(type="png", full_page=False, timeout=5000)
                if len(image_bytes) > 5 * 1024 * 1024:
                    raise ValueError("Capture exceeded evidence size budget")
                return image_bytes, {"capture_kind": "browser", "url": page.url, "requested_url": target_url,
                    "status_code": response.status, "title": (await page.title())[:200],
                    "captured_at": datetime.now(timezone.utc).isoformat(), "viewport": "1280x720",
                    "blocked_requests": blocked,
                    "limitations": "Same-host GET/HEAD only; external resources, writes and sockets blocked. Screenshot alone does not prove exploitability."}
            finally:
                await browser.close()

    @classmethod
    async def capture_url(cls, db, scan_id, asset_id, url_id, target_url,
                          trigger="homepage", finding_title=None, ctx=None):
        if not settings.browser_capture_enabled or ctx is None:
            return None
        try:
            async with cls._slots, asyncio.timeout(30):
                image_bytes, metadata = await cls._capture_browser(target_url, ctx)
                def write_capture():
                    root = SCREENSHOTS_DIR.resolve()
                    directory = contained_path(root / scan_id, root)
                    directory.mkdir(parents=True, exist_ok=True)
                    file_id = uuid.uuid4().hex
                    full_path = directory / f"{file_id}.png"
                    thumb_path = directory / f"{file_id}_thumb.jpg"
                    full_path.write_bytes(image_bytes)
                    with Image.open(io.BytesIO(image_bytes)) as img:
                        img.thumbnail((480, 270))
                        img.convert("RGB").save(thumb_path, "JPEG", quality=80)
                    digest = hashlib.sha256(image_bytes).hexdigest()
                    full_path.with_suffix(".json").write_text(json.dumps({**metadata, "sha256": digest}, indent=2), encoding="utf-8")
                    return full_path, thumb_path, digest
                full_path, thumb_path, digest = await asyncio.to_thread(write_capture)
                screenshot = Screenshot(scan_id=scan_id, asset_id=asset_id, url_id=url_id,
                    storage_path=str(full_path), thumbnail_path=str(thumb_path), viewport="1280x720",
                    status_code=metadata["status_code"], page_title=metadata["title"],
                    content_hash=digest, trigger=f"browser:{trigger}")
                db.add(screenshot)
                await db.flush()
                return screenshot
        except Exception as error:
            logger.warning("Browser capture unavailable for %s: %s", target_url, type(error).__name__)
            await ctx.emit("screenshot.unavailable", "Live browser capture unavailable; no substitute image was generated.", severity="warn")
            return None


async def run(ctx, db, root_domain):
    if not settings.browser_capture_enabled:
        await ctx.emit("screenshot.skipped", "Live screenshots disabled. Enable a sandboxed browser worker to capture actual pages.", severity="info")
        return
    assets = (await db.execute(select(Asset).where(Asset.scan_id == ctx.scan_id).limit(12))).scalars().all()
    # Bounded sequential captures use the shared browser slot across scans.
    for asset in assets:
        if not asset.hostname or not ctx.scope.host_allowed(asset.hostname):
            continue
        async with AsyncSessionLocal() as session:
            await ScreenshotEngine.capture_url(session, ctx.scan_id, asset.id, None,
                f"https://{asset.hostname}/", ctx=ctx)
            await session.commit()
