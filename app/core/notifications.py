"""
app/core/notifications.py
User-Isolated Webhook & Alert Dispatcher (Telegram, Discord, Slack)
Enforces 100% strict tenant & user data isolation.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, Optional

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import AsyncSessionLocal
from app.models.models import UserNotificationConfig

logger = logging.getLogger("notifications")


class NotificationService:
    @staticmethod
    async def get_user_config(user_id: str, db: Optional[AsyncSession] = None) -> Optional[UserNotificationConfig]:
        """Fetch notification configuration strictly for the given user_id."""
        if not user_id:
            return None

        if db:
            result = await db.execute(
                select(UserNotificationConfig).where(UserNotificationConfig.user_id == user_id)
            )
            return result.scalar_one_or_none()

        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(UserNotificationConfig).where(UserNotificationConfig.user_id == user_id)
            )
            return result.scalar_one_or_none()

    @classmethod
    async def dispatch_finding_alert(
        cls,
        user_id: Optional[str],
        scan_id: str,
        target: str,
        finding_title: str,
        severity: str,
        cve_id: Optional[str] = None,
        url: Optional[str] = None,
        detail: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Dispatch high/critical finding alert strictly to the owner user's configured webhooks."""
        if not user_id:
            return {"dispatched": False, "reason": "no_user_id"}

        try:
            config = await cls.get_user_config(user_id)
            if not config:
                return {"dispatched": False, "reason": "no_user_config"}

            sev_upper = (severity or "INFO").upper()
            is_critical = sev_upper == "CRITICAL"
            is_high = sev_upper == "HIGH"

            if is_critical and not config.notify_on_critical:
                return {"dispatched": False, "reason": "critical_notifications_disabled"}
            if is_high and not config.notify_on_high:
                return {"dispatched": False, "reason": "high_notifications_disabled"}
            if not is_critical and not is_high:
                return {"dispatched": False, "reason": "severity_below_threshold"}

            results = {}
            tasks = []

            # 1. Telegram Dispatch
            if config.telegram_enabled and config.telegram_bot_token and config.telegram_chat_id:
                tasks.append(
                    cls._send_telegram_finding(
                        config.telegram_bot_token,
                        config.telegram_chat_id,
                        target,
                        finding_title,
                        sev_upper,
                        url,
                        cve_id,
                        scan_id,
                    )
                )

            # 2. Discord Webhook Dispatch
            if config.discord_enabled and config.discord_webhook_url:
                tasks.append(
                    cls._send_discord_finding(
                        config.discord_webhook_url,
                        target,
                        finding_title,
                        sev_upper,
                        url,
                        cve_id,
                        scan_id,
                    )
                )

            # 3. Slack Webhook Dispatch
            if config.slack_enabled and config.slack_webhook_url:
                tasks.append(
                    cls._send_slack_finding(
                        config.slack_webhook_url,
                        target,
                        finding_title,
                        sev_upper,
                        url,
                        cve_id,
                        scan_id,
                    )
                )

            if tasks:
                dispatched_results = await asyncio.gather(*tasks, return_exceptions=True)
                results["tasks"] = [
                    str(r) if isinstance(r, Exception) else r for r in dispatched_results
                ]

            return {"dispatched": True, "channels_attempted": len(tasks), "results": results}

        except Exception as e:
            logger.error("Error dispatching finding alert for user %s: %s", user_id, e)
            return {"dispatched": False, "error": str(e)}

    @classmethod
    async def dispatch_scan_completed(
        cls,
        user_id: Optional[str],
        scan_id: str,
        target: str,
        metrics: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Dispatch scan completion summary strictly to the owner user's configured webhooks."""
        if not user_id:
            return {"dispatched": False, "reason": "no_user_id"}

        try:
            config = await cls.get_user_config(user_id)
            if not config or not config.notify_on_scan_complete:
                return {"dispatched": False, "reason": "scan_complete_disabled_or_no_config"}

            tasks = []
            if config.telegram_enabled and config.telegram_bot_token and config.telegram_chat_id:
                tasks.append(
                    cls._send_telegram_summary(
                        config.telegram_bot_token,
                        config.telegram_chat_id,
                        target,
                        scan_id,
                        metrics,
                    )
                )

            if config.discord_enabled and config.discord_webhook_url:
                tasks.append(
                    cls._send_discord_summary(
                        config.discord_webhook_url,
                        target,
                        scan_id,
                        metrics,
                    )
                )

            if config.slack_enabled and config.slack_webhook_url:
                tasks.append(
                    cls._send_slack_summary(
                        config.slack_webhook_url,
                        target,
                        scan_id,
                        metrics,
                    )
                )

            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

            return {"dispatched": True, "channels_attempted": len(tasks)}

        except Exception as e:
            logger.error("Error dispatching scan completion alert for user %s: %s", user_id, e)
            return {"dispatched": False, "error": str(e)}

    # ── Channel Implementation Details ───────────────────────────────────

    @staticmethod
    async def _send_telegram_finding(
        bot_token: str,
        chat_id: str,
        target: str,
        title: str,
        severity: str,
        url: Optional[str],
        cve_id: Optional[str],
        scan_id: str,
    ) -> bool:
        """Send formatted alert to Telegram Chat."""
        icon = "🔴" if severity == "CRITICAL" else "🟠"
        text = (
            f"⚡ <b>HUNTER AJA | THREAT ALERT</b>\n\n"
            f"{icon} <b>Temuan Kerentanan: {severity}</b>\n"
            f"🎯 <b>Target:</b> <code>{target}</code>\n"
            f"📌 <b>Vulnerability:</b> {title}\n"
        )
        if url:
            text += f"🌐 <b>Endpoint:</b> <code>{url}</code>\n"
        if cve_id:
            text += f"🛡️ <b>CVE ID:</b> {cve_id}\n"
        text += f"🆔 <b>Scan ID:</b> <code>{scan_id}</code>\n"
        text += f"⏱️ <i>Tervalidasi secara otonom oleh Level L4 Engine.</i>"

        api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }

        async with httpx.AsyncClient(timeout=8.0) as client:
            res = await client.post(api_url, json=payload)
            return res.status_code == 200

    @staticmethod
    async def _send_telegram_summary(
        bot_token: str,
        chat_id: str,
        target: str,
        scan_id: str,
        metrics: Dict[str, Any],
    ) -> bool:
        """Send scan complete summary to Telegram."""
        assets = metrics.get("assets", 0)
        ports = metrics.get("ports", 0)
        urls = metrics.get("urls", 0)
        findings = metrics.get("findings", 0)
        crit = metrics.get("critical", 0)
        high = metrics.get("high", 0)

        text = (
            f"🎉 <b>HUNTER AJA | SCAN COMPLETED</b>\n\n"
            f"🎯 <b>Target:</b> <code>{target}</code>\n"
            f"🆔 <b>Scan ID:</b> <code>{scan_id}</code>\n\n"
            f"📊 <b>Ringkasan Hasil Recon & Pentest:</b>\n"
            f"• Aset Aktif: <b>{assets}</b>\n"
            f"• Open Ports: <b>{ports}</b>\n"
            f"• Endpoints / URLs: <b>{urls}</b>\n"
            f"• Total Temuan Risiko: <b>{findings}</b>\n"
            f"  └ 🔴 Critical: <b>{crit}</b> | 🟠 High: <b>{high}</b>\n\n"
            f"📄 <i>Buka Dashboard Hunter Aja untuk mengunduh laporan PDF/JSON lengkap.</i>"
        )

        api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }

        async with httpx.AsyncClient(timeout=8.0) as client:
            res = await client.post(api_url, json=payload)
            return res.status_code == 200

    @staticmethod
    async def _send_discord_finding(
        webhook_url: str,
        target: str,
        title: str,
        severity: str,
        url: Optional[str],
        cve_id: Optional[str],
        scan_id: str,
    ) -> bool:
        """Send rich embed alert to Discord Webhook."""
        color = 0xDC2626 if severity == "CRITICAL" else 0xEA580C
        fields = [
            {"name": "🎯 Target Domain", "value": f"`{target}`", "inline": True},
            {"name": "⚠️ Tingkat Keparahan", "value": f"**{severity}**", "inline": True},
            {"name": "🆔 Scan ID", "value": f"`{scan_id}`", "inline": True},
        ]
        if url:
            fields.append({"name": "🌐 Vulnerable Endpoint", "value": f"`{url[:200]}`", "inline": False})
        if cve_id:
            fields.append({"name": "🛡️ CVE Reference", "value": cve_id, "inline": True})

        payload = {
            "username": "Hunter Aja L4 Threat Sentinel",
            "avatar_url": "https://img.icons8.com/color/96/shield.png",
            "embeds": [
                {
                    "title": f"🚨 [THREAT DETECTED] {title}",
                    "description": "Temuan kerentanan berhasil diverifikasi oleh Autonomous L4 Security Engine.",
                    "color": color,
                    "fields": fields,
                    "footer": {"text": "Hunter Aja Intelligence • Multi-Tenant Autonomous Pentest"},
                }
            ],
        }

        async with httpx.AsyncClient(timeout=8.0) as client:
            res = await client.post(webhook_url, json=payload)
            return res.status_code in (200, 204)

    @staticmethod
    async def _send_discord_summary(
        webhook_url: str,
        target: str,
        scan_id: str,
        metrics: Dict[str, Any],
    ) -> bool:
        """Send scan completion summary to Discord Webhook."""
        payload = {
            "username": "Hunter Aja L4 Threat Sentinel",
            "embeds": [
                {
                    "title": f"🎉 Pemindaian Selesai: {target}",
                    "description": "Seluruh fase reconnaissance, port probing, crawling, dan validasi kerentanan telah selesai.",
                    "color": 0x10B981,
                    "fields": [
                        {"name": "Aset Subdomain", "value": str(metrics.get("assets", 0)), "inline": True},
                        {"name": "Open Ports", "value": str(metrics.get("ports", 0)), "inline": True},
                        {"name": "Total Temuan", "value": str(metrics.get("findings", 0)), "inline": True},
                    ],
                    "footer": {"text": f"Scan ID: {scan_id}"},
                }
            ],
        }
        async with httpx.AsyncClient(timeout=8.0) as client:
            res = await client.post(webhook_url, json=payload)
            return res.status_code in (200, 204)

    @staticmethod
    async def _send_slack_finding(
        webhook_url: str,
        target: str,
        title: str,
        severity: str,
        url: Optional[str],
        cve_id: Optional[str],
        scan_id: str,
    ) -> bool:
        """Send formatted threat notification to Slack Webhook."""
        emoji = ":rotating_light:" if severity == "CRITICAL" else ":warning:"
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{emoji} Hunter Aja: {severity} Finding"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Target:*\n`{target}`"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n*{severity}*"},
                    {"type": "mrkdwn", "text": f"*Title:*\n{title}"},
                    {"type": "mrkdwn", "text": f"*Scan ID:*\n`{scan_id}`"},
                ],
            },
        ]
        if url:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Endpoint:* `{url}`"},
            })

        payload = {"text": f"{emoji} [{severity}] {title} on {target}", "blocks": blocks}
        async with httpx.AsyncClient(timeout=8.0) as client:
            res = await client.post(webhook_url, json=payload)
            return res.status_code == 200

    @staticmethod
    async def _send_slack_summary(
        webhook_url: str,
        target: str,
        scan_id: str,
        metrics: Dict[str, Any],
    ) -> bool:
        """Send scan complete summary to Slack."""
        payload = {
            "text": f"🎉 Scan Completed for {target} ({metrics.get('findings', 0)} findings)",
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"🎉 Scan Completed: {target}"},
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Assets:*\n{metrics.get('assets', 0)}"},
                        {"type": "mrkdwn", "text": f"*Ports:*\n{metrics.get('ports', 0)}"},
                        {"type": "mrkdwn", "text": f"*Findings:*\n{metrics.get('findings', 0)}"},
                    ],
                },
            ],
        }
        async with httpx.AsyncClient(timeout=8.0) as client:
            res = await client.post(webhook_url, json=payload)
            return res.status_code == 200


    @classmethod
    async def dispatch_diff_alert(
        cls,
        user_id: Optional[str],
        scan_id: str,
        target: str,
        diff_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Dispatch smart delta / new asset alert strictly to the owner user's configured webhooks."""
        if not user_id:
            return {"dispatched": False, "reason": "no_user_id"}

        try:
            config = await cls.get_user_config(user_id)
            if not config or not getattr(config, "notify_on_new_assets", True):
                return {"dispatched": False, "reason": "diff_alerts_disabled_or_no_config"}

            # Check if there are meaningful delta additions
            new_subdomains = diff_data.get("new_subdomains", [])
            new_ports = diff_data.get("new_ports", [])
            new_findings = diff_data.get("new_findings", [])
            changed_ips = diff_data.get("changed_ip", [])

            if not (new_subdomains or new_ports or new_findings or changed_ips):
                return {"dispatched": False, "reason": "no_delta_changes"}

            tasks = []
            if config.telegram_enabled and config.telegram_bot_token and config.telegram_chat_id:
                tasks.append(
                    cls._send_telegram_diff(
                        config.telegram_bot_token,
                        config.telegram_chat_id,
                        target,
                        scan_id,
                        diff_data,
                    )
                )

            if config.discord_enabled and config.discord_webhook_url:
                tasks.append(
                    cls._send_discord_diff(
                        config.discord_webhook_url,
                        target,
                        scan_id,
                        diff_data,
                    )
                )

            if config.slack_enabled and config.slack_webhook_url:
                tasks.append(
                    cls._send_slack_diff(
                        config.slack_webhook_url,
                        target,
                        scan_id,
                        diff_data,
                    )
                )

            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

            return {"dispatched": True, "channels_attempted": len(tasks), "delta_summary": diff_data.get("metrics", {})}

        except Exception as e:
            logger.error("Error dispatching diff alert for user %s: %s", user_id, e)
            return {"dispatched": False, "error": str(e)}

    @staticmethod
    async def _send_telegram_diff(
        bot_token: str,
        chat_id: str,
        target: str,
        scan_id: str,
        diff_data: Dict[str, Any],
    ) -> bool:
        """Send formatted smart delta alert to Telegram Chat."""
        metrics = diff_data.get("metrics", {})
        new_subdomains = diff_data.get("new_subdomains", [])
        new_ports = diff_data.get("new_ports", [])
        new_findings = diff_data.get("new_findings", [])
        changed_ips = diff_data.get("changed_ip", [])

        lines = [
            "🚨 <b>HUNTER AJA | SMART DIFF ALERT</b>",
            "🔍 <i>Perubahan attack surface baru terdeteksi!</i>",
            "",
            f"🎯 <b>Target:</b> <code>{target}</code>",
            f"🆔 <b>Scan ID:</b> <code>{scan_id}</code>",
            "",
        ]

        if new_subdomains:
            lines.append(f"🌐 <b>Subdomain Baru ({len(new_subdomains)}):</b>")
            for sub in new_subdomains[:6]:
                lines.append(f" • <code>{sub}</code>")
            if len(new_subdomains) > 6:
                lines.append(f" <i>...dan {len(new_subdomains)-6} subdomain lainnya.</i>")
            lines.append("")

        if new_ports:
            lines.append(f"📡 <b>Port Baru Terbuka ({len(new_ports)}):</b>")
            for p in new_ports[:6]:
                p_host = p.get("hostname", "")
                p_num = p.get("port", "")
                p_srv = p.get("service") or "tcp"
                lines.append(f" • <b>{p_host}:{p_num}</b> ({p_srv})")
            if len(new_ports) > 6:
                lines.append(f" <i>...dan {len(new_ports)-6} port lainnya.</i>")
            lines.append("")

        if new_findings:
            lines.append(f"🛡️ <b>Temuan Kerentanan Baru ({len(new_findings)}):</b>")
            for f in new_findings[:5]:
                sev = f.get("severity", "MEDIUM")
                icon = "🔴" if sev == "CRITICAL" else "🟠" if sev == "HIGH" else "🟡"
                f_title = f.get("title", "")
                lines.append(f" • {icon} <b>{f_title}</b> [{sev}]")
            lines.append("")

        if changed_ips:
            lines.append(f"🔄 <b>Perubahan IP ({len(changed_ips)}):</b>")
            for cip in changed_ips[:4]:
                h = cip.get("hostname", "")
                prev = cip.get("previous_ip", "")
                cur = cip.get("current_ip", "")
                lines.append(f" • <code>{h}</code>: {prev} ➔ {cur}")
            lines.append("")

        lines.append("⚡ <i>Segera verifikasi perubahan ini di Hunter Aja Dashboard.</i>")
        text = "\n".join(lines)

        api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.post(api_url, json=payload)
                return res.status_code == 200
        except Exception as err:
            logger.warning("Telegram diff dispatch failed: %s", err)
            return False

    @staticmethod
    async def _send_discord_diff(
        webhook_url: str,
        target: str,
        scan_id: str,
        diff_data: Dict[str, Any],
    ) -> bool:
        """Send formatted smart delta alert to Discord Webhook."""
        new_subdomains = diff_data.get("new_subdomains", [])
        new_ports = diff_data.get("new_ports", [])
        new_findings = diff_data.get("new_findings", [])
        changed_ips = diff_data.get("changed_ip", [])

        fields = [
            {"name": "🎯 Target", "value": f"`{target}`", "inline": True},
            {"name": "🆔 Scan ID", "value": f"`{scan_id}`", "inline": True},
        ]

        if new_subdomains:
            sub_list = "\n".join([f"• `{s}`" for s in new_subdomains[:8]])
            if len(new_subdomains) > 8:
                sub_list += f"\n*...dan {len(new_subdomains)-8} lainnya*"
            fields.append({"name": f"🌐 Subdomain Baru ({len(new_subdomains)})", "value": sub_list, "inline": False})

        if new_ports:
            port_list = "\n".join([f"• **{p.get('hostname')}:{p.get('port')}** ({p.get('service') or 'tcp'})" for p in new_ports[:8]])
            if len(new_ports) > 8:
                port_list += f"\n*...dan {len(new_ports)-8} lainnya*"
            fields.append({"name": f"📡 Port Baru Terbuka ({len(new_ports)})", "value": port_list, "inline": False})

        if new_findings:
            fnd_list = "\n".join([f"• [{f.get('severity', 'MEDIUM')}] **{f.get('title')}**" for f in new_findings[:6]])
            fields.append({"name": f"🛡️ Kerentanan Baru ({len(new_findings)})", "value": fnd_list, "inline": False})

        payload = {
            "username": "Hunter Aja Sentinel",
            "avatar_url": "https://raw.githubusercontent.com/hunteraja/assets/main/icon.png",
            "embeds": [
                {
                    "title": f"🚨 [SMART DIFF ALERT] Perubahan Aset Baru: {target}",
                    "description": "Perbandingan dengan scan sebelumnya mendeteksi eksposur aset / port / risiko baru pada target.",
                    "color": 0xF59E0B if not new_findings else 0xEF4444,
                    "fields": fields,
                    "footer": {"text": "Hunter Aja • Level L4 Attack Surface Intelligence"},
                }
            ],
        }

        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.post(webhook_url, json=payload)
                return res.status_code in (200, 204)
        except Exception as err:
            logger.warning("Discord diff dispatch failed: %s", err)
            return False

    @staticmethod
    async def _send_slack_diff(
        webhook_url: str,
        target: str,
        scan_id: str,
        diff_data: Dict[str, Any],
    ) -> bool:
        """Send formatted smart delta alert to Slack Webhook."""
        new_subdomains = diff_data.get("new_subdomains", [])
        new_ports = diff_data.get("new_ports", [])
        new_findings = diff_data.get("new_findings", [])

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"🚨 Hunter Aja: Smart Diff Alert ({target})"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Target:*\n`{target}`"},
                    {"type": "mrkdwn", "text": f"*Scan ID:*\n`{scan_id}`"},
                    {"type": "mrkdwn", "text": f"*New Subdomains:*\n{len(new_subdomains)}"},
                    {"type": "mrkdwn", "text": f"*New Ports:*\n{len(new_ports)}"},
                ],
            },
        ]

        payload = {"text": f"🚨 [DIFF ALERT] Perubahan aset baru terdeteksi pada {target}", "blocks": blocks}
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.post(webhook_url, json=payload)
                return res.status_code == 200
        except Exception as err:
            logger.warning("Slack diff dispatch failed: %s", err)
            return False

    @classmethod
    async def test_user_channel(
        cls,
        channel: str,
        telegram_token: Optional[str] = None,
        telegram_chat_id: Optional[str] = None,
        discord_webhook: Optional[str] = None,
        slack_webhook: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Send a live test message to verify user-entered webhook/credentials."""
        channel_lower = (channel or "").lower().strip()
        try:
            if channel_lower == "telegram":
                if not telegram_token or not telegram_chat_id:
                    return {"success": False, "detail": "Telegram Bot Token dan Chat ID wajib diisi."}
                ok = await cls._send_telegram_finding(
                    bot_token=telegram_token,
                    chat_id=telegram_chat_id,
                    target="test.example.com",
                    title="Uji Coba Integrasi Notifikasi Telegram",
                    severity="INFO",
                    url="https://test.example.com/api/health",
                    cve_id="TEST-NOTIFICATION",
                    scan_id="test_scan_verification",
                )
                return {"success": ok, "detail": "Pesan tes berhasil dikirim ke Telegram!" if ok else "Gagal mengirim ke Telegram. Pastikan Bot Token dan Chat ID valid serta bot sudah di-Start (/start)."}

            elif channel_lower == "discord":
                if not discord_webhook:
                    return {"success": False, "detail": "Discord Webhook URL wajib diisi."}
                ok = await cls._send_discord_finding(
                    webhook_url=discord_webhook,
                    target="test.example.com",
                    title="Uji Coba Integrasi Notifikasi Discord",
                    severity="INFO",
                    url="https://test.example.com/webhook/test",
                    cve_id="TEST-NOTIFICATION",
                    scan_id="test_scan_verification",
                )
                return {"success": ok, "detail": "Embed tes berhasil dikirim ke Discord!" if ok else "Gagal mengirim ke Discord Webhook URL. Pastikan URL webhook valid."}

            elif channel_lower == "slack":
                if not slack_webhook:
                    return {"success": False, "detail": "Slack Webhook URL wajib diisi."}
                ok = await cls._send_slack_finding(
                    webhook_url=slack_webhook,
                    target="test.example.com",
                    title="Uji Coba Integrasi Notifikasi Slack",
                    severity="INFO",
                    url="https://test.example.com/slack/test",
                    cve_id="TEST-NOTIFICATION",
                    scan_id="test_scan_verification",
                )
                return {"success": ok, "detail": "Pesan tes berhasil dikirim ke Slack!" if ok else "Gagal mengirim ke Slack Webhook URL. Pastikan URL webhook valid."}

            return {"success": False, "detail": f"Channel '{channel}' tidak dikenali."}

        except Exception as err:
            return {"success": False, "detail": f"Terjadi kesalahan saat menguji notifikasi: {err}"}


notification_service = NotificationService()
