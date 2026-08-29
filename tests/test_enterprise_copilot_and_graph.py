"""
tests/test_enterprise_copilot_and_graph.py
Comprehensive test suite for Enterprise Upgrades:
- User-Isolated Webhook & Alert Dispatcher (Telegram, Discord, Slack)
- OpenAPI 3.0.3 Specification Auto-Generator
- Interactive Pentest AI Copilot & Deterministic Reasoning
- WAF Fingerprinter & Smart Evasion Engine
"""
import uuid
import pytest
from httpx import ASGITransport, AsyncClient
from unittest.mock import AsyncMock, patch

from app.core.db import AsyncSessionLocal
from app.core.notifications import NotificationService, notification_service
from app.discovery.waf_detector import WafDetector, waf_detector
from app.ai.copilot import PentestCopilot, pentest_copilot
from app.reporting.openapi_generator import OpenApiGenerator
from app.main import app
from app.models.models import Asset, Finding, Parameter, Scan, URL, User, UserNotificationConfig
from app.core.auth import hash_password, create_access_token


@pytest.fixture
async def enterprise_fixture():
    async with AsyncSessionLocal() as db:
        user_a_id = f"user_a_{uuid.uuid4().hex[:6]}"
        user_b_id = f"user_b_{uuid.uuid4().hex[:6]}"
        pwd_hash = hash_password("Password123!")

        user_a = User(
            id=user_a_id,
            username=f"usera_{uuid.uuid4().hex[:4]}",
            email=f"usera_{uuid.uuid4().hex[:4]}@target.com",
            hashed_password=pwd_hash,
            role="user",
            is_active=True,
        )
        user_b = User(
            id=user_b_id,
            username=f"userb_{uuid.uuid4().hex[:4]}",
            email=f"userb_{uuid.uuid4().hex[:4]}@target.com",
            hashed_password=pwd_hash,
            role="user",
            is_active=True,
        )
        db.add(user_a)
        db.add(user_b)
        await db.flush()

        # Scan for User A
        scan_id = f"scan_{uuid.uuid4().hex[:6]}"
        scan = Scan(
            id=scan_id,
            user_id=user_a_id,
            root_domain="target-enterprise.com",
            status="completed",
            profile="adversary_simulation",
            validation_level="L4_HIGH_RISK",
        )
        db.add(scan)
        await db.flush()

        # Asset & Endpoints for scan
        asset = Asset(
            id=f"ast_{uuid.uuid4().hex[:6]}",
            scan_id=scan_id,
            hostname="api.target-enterprise.com",
            fingerprint="api.target-enterprise.com",
            ip="192.168.1.50",
            asset_type="subdomain",
        )
        db.add(asset)
        await db.flush()

        url_1 = URL(
            id=f"url_{uuid.uuid4().hex[:6]}",
            asset_id=asset.id,
            url="https://api.target-enterprise.com/v1/users?search=admin&page=1",
            scheme="https",
            host="api.target-enterprise.com",
            path="/v1/users",
            query="search=admin&page=1",
            status_code=200,
            title="User Management API",
        )
        url_2 = URL(
            id=f"url_{uuid.uuid4().hex[:6]}",
            asset_id=asset.id,
            url="https://api.target-enterprise.com/v1/checkout",
            scheme="https",
            host="api.target-enterprise.com",
            path="/v1/checkout",
            status_code=201,
            title="Checkout API",
        )
        db.add(url_1)
        db.add(url_2)
        await db.flush()

        param_1 = Parameter(
            id=f"prm_{uuid.uuid4().hex[:6]}",
            url_id=url_1.id,
            name="search",
            location="query",
            type="string",
        )
        param_2 = Parameter(
            id=f"prm_{uuid.uuid4().hex[:6]}",
            url_id=url_1.id,
            name="page",
            location="query",
            type="integer",
        )
        db.add(param_1)
        db.add(param_2)

        finding = Finding(
            id=f"fnd_{uuid.uuid4().hex[:6]}",
            scan_id=scan_id,
            asset_id=asset.id,
            finding_type="vulnerability",
            title="SQL Injection in Search Query Parameter",
            severity="CRITICAL",
            confidence="CONFIRMED",
            cve_id="CVE-2024-SQLI-TEST",
            evidence={"url": url_1.url, "parameter": "search"},
        )
        db.add(finding)

        await db.commit()

        token_a = create_access_token(user_id=user_a.id, username=user_a.username, role=user_a.role, password_hash=user_a.hashed_password)
        token_b = create_access_token(user_id=user_b.id, username=user_b.username, role=user_b.role, password_hash=user_b.hashed_password)

        return {
            "user_a": user_a,
            "user_b": user_b,
            "headers_a": {"Authorization": f"Bearer {token_a}"},
            "headers_b": {"Authorization": f"Bearer {token_b}"},
            "scan_id": scan_id,
        }


@pytest.mark.anyio
async def test_user_notification_config_tenant_isolation(enterprise_fixture):
    """Verify that User A and User B maintain strict isolation of their notification configs."""
    fixture = enterprise_fixture
    headers_a = fixture["headers_a"]
    headers_b = fixture["headers_b"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        # 1. User A sets Telegram & Discord configurations
        res_a = await client.put(
            "/api/user/notifications",
            headers=headers_a,
            json={
                "telegram_bot_token": "TOKEN_A_12345",
                "telegram_chat_id": "CHAT_A_9999",
                "telegram_enabled": True,
                "discord_webhook_url": "https://discord.com/api/webhooks/USER_A",
                "discord_enabled": True,
                "slack_webhook_url": "",
                "slack_enabled": False,
                "notify_on_critical": True,
                "notify_on_high": True,
                "notify_on_scan_complete": True,
            },
        )
        assert res_a.status_code == 200

        # 2. User A fetches own config
        get_a = await client.get("/api/user/notifications", headers=headers_a)
        assert get_a.status_code == 200
        data_a = get_a.json()
        assert data_a["telegram_bot_token"] == "TOKEN_A_12345"
        assert data_a["telegram_chat_id"] == "CHAT_A_9999"
        assert data_a["discord_webhook_url"] == "https://discord.com/api/webhooks/USER_A"

        # 3. User B fetches config — MUST NOT see User A's data
        get_b = await client.get("/api/user/notifications", headers=headers_b)
        assert get_b.status_code == 200
        data_b = get_b.json()
        assert data_b["telegram_bot_token"] == ""
        assert data_b["discord_webhook_url"] == ""
        assert data_b["telegram_enabled"] is False


@pytest.mark.anyio
async def test_notification_dispatcher_execution(enterprise_fixture, monkeypatch):
    """Test notification dispatch logic for finding alerts and scan complete."""
    fixture = enterprise_fixture
    user_a = fixture["user_a"]
    scan_id = fixture["scan_id"]

    async with AsyncSessionLocal() as db:
        cfg = UserNotificationConfig(
            id=f"cfg_{uuid.uuid4().hex[:6]}",
            user_id=user_a.id,
            telegram_bot_token="123:ABC",
            telegram_chat_id="999",
            telegram_enabled=True,
            discord_webhook_url="https://discord.com/api/webhooks/test",
            discord_enabled=True,
            notify_on_critical=True,
            notify_on_high=True,
            notify_on_scan_complete=True,
        )
        db.add(cfg)
        await db.commit()

    mock_send = AsyncMock(return_value=True)
    monkeypatch.setattr(NotificationService, "_send_telegram_finding", mock_send)
    monkeypatch.setattr(NotificationService, "_send_discord_finding", mock_send)
    monkeypatch.setattr(NotificationService, "_send_telegram_summary", mock_send)

    # Dispatch Finding Alert
    res = await notification_service.dispatch_finding_alert(
        user_id=user_a.id,
        scan_id=scan_id,
        target="target-enterprise.com",
        finding_title="SQL Injection",
        severity="CRITICAL",
        cve_id="CVE-2024-SQLI-TEST",
        url="https://api.target-enterprise.com/v1/users",
    )
    assert res["dispatched"] is True

    # Dispatch Scan Complete
    res_comp = await notification_service.dispatch_scan_completed(
        user_id=user_a.id,
        scan_id=scan_id,
        target="target-enterprise.com",
        metrics={"assets": 5, "ports": 3, "findings": 2, "critical": 1, "high": 1},
    )
    assert res_comp["dispatched"] is True


@pytest.mark.anyio
async def test_openapi_specification_generator(enterprise_fixture):
    """Test automated OpenAPI 3.0.3 generator endpoint."""
    fixture = enterprise_fixture
    scan_id = fixture["scan_id"]
    headers = fixture["headers_a"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        res = await client.get(f"/api/scans/{scan_id}/export/openapi.json", headers=headers)
        assert res.status_code == 200
        spec = res.json()
        assert spec["openapi"] == "3.0.3"
        assert "paths" in spec
        assert "/v1/users" in spec["paths"]
        assert "get" in spec["paths"]["/v1/users"]
        assert len(spec["paths"]["/v1/users"]["get"]["parameters"]) >= 1


@pytest.mark.anyio
async def test_waf_detector_analysis():
    """Test WAF detector signature matching and evasion guidance."""
    # 1. Cloudflare Test
    cf_res = waf_detector.analyze_response(
        status_code=403,
        headers={"Server": "cloudflare", "cf-ray": "82348abc123-SIN"},
        cookies={"__cfduid": "abc123def"},
        body="<html><body>Attention Required! | Cloudflare</body></html>",
    )
    assert cf_res["detected"] is True
    assert cf_res["vendor"] == "Cloudflare"
    assert cf_res["confidence"] > 0.8
    assert len(cf_res["evasion_hints"]) >= 1

    # 2. AWS WAF Test
    aws_res = waf_detector.analyze_response(
        status_code=403,
        headers={"Server": "awselb/2.0", "x-amzn-requestid": "req-1234"},
        body="403 Forbidden - Request blocked by AWS WAF",
    )
    assert aws_res["detected"] is True
    assert aws_res["vendor"] == "AWS WAF"

    # 3. Clean Origin (No WAF)
    clean_res = waf_detector.analyze_response(
        status_code=200,
        headers={"Server": "nginx/1.24.0", "Content-Type": "text/html"},
        body="<h1>Welcome to Clean Server</h1>",
    )
    assert clean_res["detected"] is False
    assert clean_res["vendor"] is None


@pytest.mark.anyio
async def test_pentest_ai_copilot(enterprise_fixture):
    """Test AI Copilot chat reasoning, PoC generator, and remediation patches."""
    fixture = enterprise_fixture
    scan_id = fixture["scan_id"]
    headers = fixture["headers_a"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        # 1. Ask for Python PoC Exploit
        res_poc = await client.post(
            "/api/ai/copilot/chat",
            json={"message": "Generate Python PoC exploit script untuk validasi", "scan_id": scan_id},
            headers=headers,
        )
        assert res_poc.status_code == 200
        data_poc = res_poc.json()
        assert "reply" in data_poc
        assert "import requests" in data_poc["reply"]

        # 2. Ask for Code Remediation Patch
        res_fix = await client.post(
            "/api/ai/copilot/chat",
            json={"message": "Tampilkan patch remediasi kode untuk developer", "scan_id": scan_id},
            headers=headers,
        )
        assert res_fix.status_code == 200
        data_fix = res_fix.json()
        assert "PHP" in data_fix["reply"] or "PDO" in data_fix["reply"] or "parameterized" in data_fix["reply"].lower()

        # 3. Ask for Attack Vector Analysis
        res_vector = await client.post(
            "/api/ai/copilot/chat",
            json={"message": "Analisis attack vector dan surface", "scan_id": scan_id},
            headers=headers,
        )
        assert res_vector.status_code == 200
        data_vector = res_vector.json()
        assert "target-enterprise.com" in data_vector["reply"] or "Surface" in data_vector["reply"]
