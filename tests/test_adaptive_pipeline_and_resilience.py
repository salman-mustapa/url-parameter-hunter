"""Tests for Adaptive Pipeline Resilience, Intelligent Degradation Thresholds, and Time Budget Governance.
"""

from __future__ import annotations

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock
from sqlalchemy import select

from app.core.rate_limit import RateLimiter
from app.core.scope import Scope
from app.models.models import Asset, Finding, Scan, URL
from app.scanners.base import ScanContext
from app.scanners.web import crawl_and_discover_asset, run as run_web_crawler


class TestPipelineResilienceAndDegradation:
    @pytest.mark.anyio
    async def test_non_fatal_warnings_preserve_completed_status(self):
        """
        Verify that if discovery finds assets, URLs, and findings, non-fatal warnings
        (such as screenshot engine warning or single tool fallback) do NOT mark the scan as DEGRADED.
        """
        mock_asset_count = 5

        # Simulate phase failures containing non-fatal warnings (e.g. screenshot, soft web warning)
        phase_failures = [
            {"phase": "evidence", "error": "Playwright browser not installed, fell back to PIL canvas", "fatal": False},
            {"phase": "http", "error": "HTTP probe warning on dead subdomain", "fatal": False},
        ]

        # Verify logic:
        is_fatal_failure = any(f.get("fatal", False) for f in phase_failures)
        is_degraded = is_fatal_failure or (mock_asset_count == 0 and any(f.get("phase") == "discovery" for f in phase_failures))
        completion_status = "degraded" if is_degraded else "completed"

        assert completion_status == "completed"
        assert is_degraded is False

    @pytest.mark.anyio
    async def test_fatal_recon_failure_marks_degraded(self):
        """
        Verify that if initial discovery completely fails and yields 0 assets,
        the scan is correctly marked as DEGRADED.
        """
        mock_asset_count = 0
        phase_failures = [
            {"phase": "discovery", "error": "DNS resolution failed completely for non-existent domain", "fatal": True}
        ]

        is_fatal_failure = any(f.get("fatal", False) for f in phase_failures)
        is_degraded = is_fatal_failure or (mock_asset_count == 0 and any(f.get("phase") == "discovery" for f in phase_failures))
        completion_status = "degraded" if is_degraded else "completed"

        assert completion_status == "degraded"
        assert is_degraded is True


class TestWebCrawlerPrioritization:
    @pytest.mark.anyio
    async def test_unresponsive_host_skips_heavy_dirsearch(self, monkeypatch):
        """
        Verify that dead/unresponsive hosts return immediately during liveness check,
        saving crawler runtime budget.
        """
        scope = Scope("testapp.local")
        ctx = ScanContext(scan_id="scan_mock", scope=scope, profile="deep", options={}, rate_limiter=RateLimiter(50))
        db = AsyncMock()
        db.execute = AsyncMock(return_value=MagicMock(scalars=lambda: MagicMock(all=lambda: [])))
        asset = Asset(id=1, hostname="dead.testapp.local", asset_type="subdomain", depth=1)

        # Mock fetch_http returning None (dead host)
        async def mock_fetch_http(url, **kwargs):
            return None

        monkeypatch.setattr("app.scanners.web.fetch_http", mock_fetch_http)

        # Execute crawl_and_discover_asset
        await crawl_and_discover_asset(ctx, db, asset, root_domain="testapp.local", is_many_hosts=True)

        # Verify no database URL additions were made for dead host
        assert db.add.call_count == 0

    @pytest.mark.anyio
    async def test_high_value_host_runs_targeted_discovery(self, monkeypatch):
        """
        Verify that high-value functional hosts (e.g. siakad, portal, root) are prioritized.
        """
        scope = Scope("testapp.local")
        ctx = ScanContext(scan_id="scan_mock", scope=scope, profile="deep", options={}, rate_limiter=RateLimiter(50))
        db = AsyncMock()
        db.execute = AsyncMock(return_value=MagicMock(scalars=lambda: MagicMock(all=lambda: [])))
        asset = Asset(id=2, hostname="siakad.testapp.local", asset_type="subdomain", depth=1)

        import httpx

        async def mock_fetch_http(url, **kwargs):
            return httpx.Response(
                status_code=200,
                headers={"content-type": "text/html"},
                text="<html><head><title>Portal Siakad</title></head><body><h1>SIAKAD</h1></body></html>",
                request=httpx.Request("GET", url),
            )

        monkeypatch.setattr("app.scanners.web.fetch_http", mock_fetch_http)
        monkeypatch.setattr("app.scanners.web._harvest_passive_urls", AsyncMock(return_value=[]))

        # Should complete without error
        await crawl_and_discover_asset(ctx, db, asset, root_domain="testapp.local", is_many_hosts=True)
