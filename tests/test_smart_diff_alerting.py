import asyncio
import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select

from app.main import app
from app.core.db import async_session_scope, AsyncSessionLocal
from app.models.models import User, Scan, Asset, Port, Finding, UserNotificationConfig
from app.differential.engine import differential_engine
from app.core.notifications import notification_service
from app.core.auth import create_access_token


@pytest.mark.asyncio
async def test_differential_engine_delta_computation():
    """Verify that DifferentialEngine correctly computes new subdomains, ports, findings, and changed IPs."""
    async with async_session_scope() as db:
        # 1. Create Scan 1
        scan1 = Scan(root_domain="target-diff.com", status="completed")
        db.add(scan1)
        await db.flush()

        asset1 = Asset(scan_id=scan1.id, asset_type="domain", fingerprint="fp-diff-1", hostname="target-diff.com", ip="1.1.1.1", status="active")
        asset2 = Asset(scan_id=scan1.id, asset_type="subdomain", fingerprint="fp-diff-2", hostname="old.target-diff.com", ip="1.1.1.2", status="active")
        db.add_all([asset1, asset2])
        await db.flush()

        port1 = Port(asset_id=asset1.id, port=80, protocol="tcp", service="http")
        finding1 = Finding(scan_id=scan1.id, finding_type="VULNERABILITY", title="Old Disclosure", severity="LOW")
        db.add_all([port1, finding1])

        # 2. Create Scan 2 (New assets, new ports, new findings)
        scan2 = Scan(root_domain="target-diff.com", status="completed")
        db.add(scan2)
        await db.flush()

        asset1_v2 = Asset(scan_id=scan2.id, asset_type="domain", fingerprint="fp-diff-1v2", hostname="target-diff.com", ip="2.2.2.2", status="active")  # Changed IP
        asset3_new = Asset(scan_id=scan2.id, asset_type="subdomain", fingerprint="fp-diff-3", hostname="dev-api.target-diff.com", ip="1.1.1.3", status="active")  # New subdomain
        db.add_all([asset1_v2, asset3_new])
        await db.flush()

        port1_v2 = Port(asset_id=asset1_v2.id, port=80, protocol="tcp", service="http")
        port2_new = Port(asset_id=asset3_new.id, port=8443, protocol="tcp", service="https-alt")  # New port
        finding1_v2 = Finding(scan_id=scan2.id, finding_type="VULNERABILITY", title="Old Disclosure", severity="LOW")
        finding2_new = Finding(scan_id=scan2.id, finding_type="VULNERABILITY", title="Critical SQLi on Dev API", severity="CRITICAL")  # New finding
        db.add_all([port1_v2, port2_new, finding1_v2, finding2_new])
        await db.commit()

        # Run comparison
        diff = await differential_engine.compare(db, current_scan_id=scan2.id, previous_scan_id=scan1.id)

        assert diff["metrics"]["new_assets_count"] == 1
        assert "dev-api.target-diff.com" in diff["new_subdomains"]
        assert diff["metrics"]["new_ports_count"] == 1
        assert any(p["port"] == 8443 for p in diff["new_ports"])
        assert diff["metrics"]["new_findings_count"] == 1
        assert any(f["title"] == "Critical SQLi on Dev API" for f in diff["new_findings"])
        assert len(diff["changed_ip"]) == 1
        assert diff["changed_ip"][0]["hostname"] == "target-diff.com"
        assert diff["changed_ip"][0]["current_ip"] == "2.2.2.2"


@pytest.mark.asyncio
async def test_smart_diff_notification_dispatch_isolation(monkeypatch):
    """Ensure smart diff notifications strictly respect user config and tenant isolation."""
    # Mock httpx POST in notification_service
    sent_requests = []

    async def mock_post(self, url, *args, **kwargs):
        sent_requests.append({"url": str(url), "json": kwargs.get("json", {})})
        class MockResp:
            status_code = 200
            def json(self):
                return {"ok": True}
        return MockResp()

    import httpx
    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    async with async_session_scope() as db:
        user_a = User(email="user_a_diff@example.com", username="user_a_diff", hashed_password="hashed_pw_123")
        user_b = User(email="user_b_diff@example.com", username="user_b_diff", hashed_password="hashed_pw_123")
        db.add_all([user_a, user_b])
        await db.flush()

        cfg_a = UserNotificationConfig(
            user_id=user_a.id,
            telegram_bot_token="BOT_TOKEN_USER_A",
            telegram_chat_id="CHAT_ID_A",
            telegram_enabled=True,
            discord_webhook_url="https://discord.com/api/webhooks/user_a_webhook",
            discord_enabled=True,
            notify_on_new_assets=True,
        )
        cfg_b = UserNotificationConfig(
            user_id=user_b.id,
            telegram_bot_token="BOT_TOKEN_USER_B",
            telegram_chat_id="CHAT_ID_B",
            telegram_enabled=True,
            notify_on_new_assets=False, # Disabled for user B
        )
        db.add_all([cfg_a, cfg_b])
        await db.commit()

        sample_diff = {
            "metrics": {"new_assets_count": 1, "new_ports_count": 1, "new_findings_count": 1},
            "new_subdomains": ["admin-new.example.com"],
            "new_ports": [{"hostname": "admin-new.example.com", "port": 3306, "service": "mysql"}],
            "new_findings": [{"title": "Exposed Database", "severity": "HIGH"}],
            "changed_ip": [],
        }

        # 1. Dispatch for User A (Enabled -> Should send to Telegram & Discord)
        res_a = await notification_service.dispatch_diff_alert(
            user_id=user_a.id,
            scan_id="scan_a_123",
            target="example.com",
            diff_data=sample_diff,
        )
        assert res_a["dispatched"] is True
        assert res_a["channels_attempted"] == 2

        # Verify dispatched content contains User A's token / webhook and target
        tg_req = next((r for r in sent_requests if "BOT_TOKEN_USER_A" in r["url"]), None)
        assert tg_req is not None
        assert "admin-new.example.com" in tg_req["json"]["text"]
        assert "3306" in tg_req["json"]["text"]

        dc_req = next((r for r in sent_requests if "user_a_webhook" in r["url"]), None)
        assert dc_req is not None
        assert "admin-new.example.com" in str(dc_req["json"])

        # 2. Dispatch for User B (notify_on_new_assets is False -> Should not send)
        res_b = await notification_service.dispatch_diff_alert(
            user_id=user_b.id,
            scan_id="scan_b_123",
            target="example.com",
            diff_data=sample_diff,
        )
        assert res_b["dispatched"] is False
        assert res_b["reason"] == "diff_alerts_disabled_or_no_config"


@pytest.mark.asyncio
async def test_api_auto_diff_endpoint():
    """Verify GET /api/scans/{scan_id}/diff/auto retrieves previous scan delta."""
    async with async_session_scope() as db:
        user = User(email="test_auto_diff@example.com", username="test_auto_diff", hashed_password="hashed_pw_123")
        db.add(user)
        await db.flush()

        s1 = Scan(root_domain="autodiff.com", status="completed", user_id=user.id)
        db.add(s1)
        await db.flush()

        a1 = Asset(scan_id=s1.id, asset_type="domain", fingerprint="fp-autodiff-1", hostname="autodiff.com", ip="10.0.0.1", status="active")
        db.add(a1)
        await db.flush()

        await asyncio.sleep(0.05)

        s2 = Scan(root_domain="autodiff.com", status="completed", user_id=user.id)
        db.add(s2)
        await db.flush()

        a2 = Asset(scan_id=s2.id, asset_type="domain", fingerprint="fp-autodiff-2", hostname="autodiff.com", ip="10.0.0.1", status="active")
        a3 = Asset(scan_id=s2.id, asset_type="subdomain", fingerprint="fp-autodiff-3", hostname="new-sub.autodiff.com", ip="10.0.0.2", status="active")
        db.add_all([a2, a3])
        await db.commit()

        token = create_access_token(user_id=user.id, username=user.username, role="user", password_hash=user.hashed_password)
        headers = {"Authorization": f"Bearer {token}"}

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.get(f"/api/scans/{s2.id}/diff/auto", headers=headers)
            assert res.status_code == 200
            data = res.json()
            assert data["has_previous"] is True
            assert data["previous_scan_id"] == s1.id
            assert "new-sub.autodiff.com" in data["diff"]["new_subdomains"]
