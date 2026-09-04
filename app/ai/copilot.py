"""
app/ai/copilot.py
Interactive Pentest AI Copilot & Autonomous Assistant
Context-aware reasoning, PoC generator, remediation patch synthesizer, and attack path analyst.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.gateway import ai_gateway, AiGateway
from app.core.db import AsyncSessionLocal
from app.models.models import Artifact, Asset, Finding, Parameter, Port, Scan, URL

logger = logging.getLogger("ai.copilot")


class PentestCopilot:
    @classmethod
    async def chat(
        cls,
        message: str,
        scan_id: Optional[str] = None,
        history: Optional[List[Dict[str, str]]] = None,
    ) -> Dict[str, Any]:
        """Handle interactive chat queries with contextual awareness of active scan assets & findings."""
        history = history or []
        msg_clean = message.strip()

        # 1. Fetch scan context if scan_id is provided
        scan_ctx: Dict[str, Any] = {}
        if scan_id:
            scan_ctx = await cls._fetch_scan_context(scan_id)

        target = scan_ctx.get("target", "Target Belum Dipilih")
        findings = scan_ctx.get("findings", [])
        assets = scan_ctx.get("assets", [])
        ports = scan_ctx.get("ports", [])
        artifacts = scan_ctx.get("artifacts", [])

        # 2. Check if cloud AI gateway has active external LLM provider configured
        try:
            from app.ai.gateway import ZeroResourceHeuristicProvider, UniversalAutoProvider
            provider = ai_gateway.active_provider
            has_cloud = False
            if isinstance(provider, UniversalAutoProvider):
                has_cloud = provider.is_available()
            elif not isinstance(provider, ZeroResourceHeuristicProvider):
                has_cloud = provider.is_available()

            if has_cloud:
                system_prompt = (
                    "Anda adalah Hunter Aja AI Copilot — Asisten Ahli Keamanan Siber & Autonomous Pentesting.\n"
                    f"Konteks Target Aktif: {target}\n"
                    f"Aset Subdomain: {len(assets)} terdeteksi\n"
                    f"Open Ports: {', '.join(ports[:10]) if ports else 'Belum ada'}\n"
                    f"Temuan Kerentanan ({len(findings)}): {', '.join([f['title'] + ' (' + f['severity'] + ')' for f in findings[:6]])}\n\n"
                    "Panduan Jawaban:\n"
                    "1. Berikan penjelasan teknis yang mendalam, tepat sasaran, dan akurat.\n"
                    "2. Jika diminta PoC, sertakan script Python `requests` yang aman dan modular dengan penanganan error.\n"
                    "3. Jika diminta Remediasi, berikan contoh kode perbaikan nyata (PHP / Python / Node.js / Go).\n"
                    "4. Gunakan format Markdown yang rapi dengan code block."
                )
                # Older templates used escaped newlines; normalize them before
                # sending context to a provider or rendering Markdown in the UI.
                system_prompt = system_prompt.replace("\\n", "\n")
                res = await ai_gateway.complete(msg_clean, system=system_prompt)
                ai_text = res.get("content") or res.get("text")
                if ai_text and len(ai_text) > 40 and res.get("status") == "success" and res.get("provider") != "zero_resource_heuristic":
                    return {
                        "reply": ai_text,
                        "source": "cloud_llm",
                        "model": res.get("provider", "cloud_ai"),
                        "scan_id": scan_id,
                        "suggested_actions": cls._get_suggested_actions(msg_clean, findings),
                    }
        except Exception as err:
            logger.warning("Cloud AI Copilot call skipped/failed, using local reasoning engine: %s", err)

        # 3. Built-in Deterministic Pentest Copilot Reasoning Engine
        reply = cls._synthesize_deterministic_response(msg_clean, scan_ctx).replace("\\n", "\n")
        return {
            "reply": reply,
            "source": "local_security_engine",
            "model": "HunterAja-L4-Deterministic-AST",
            "scan_id": scan_id,
            "suggested_actions": cls._get_suggested_actions(msg_clean, findings),
        }

    @classmethod
    async def _fetch_scan_context(cls, scan_id: str) -> Dict[str, Any]:
        """Load structured context from database for a given scan."""
        try:
            async with AsyncSessionLocal() as db:
                scan = await db.get(Scan, scan_id)
                if not scan:
                    return {}

                assets = (await db.execute(select(Asset).where(Asset.scan_id == scan_id))).scalars().all()
                asset_ids = [a.id for a in assets]

                ports = (await db.execute(select(Port).where(Port.asset_id.in_(asset_ids)))).scalars().all() if asset_ids else []
                findings = (await db.execute(select(Finding).where(Finding.scan_id == scan_id))).scalars().all()
                artifacts = (await db.execute(select(Artifact).where(Artifact.scan_id == scan_id))).scalars().all()

                return {
                    "scan_id": scan.id,
                    "target": scan.root_domain,
                    "status": scan.status,
                    "profile": scan.profile,
                    "assets": [a.hostname or a.ip for a in assets if a.hostname or a.ip],
                    "ports": [f"{p.ip or 'host'}:{getattr(p, 'port', 80)} ({p.service or 'tcp'})" for p in ports],
                    "findings": [
                        {
                            "id": f.id,
                            "title": f.title,
                            "severity": f.severity or "MEDIUM",
                            "confidence": f.confidence or 0.8,
                            "cvss": f.cvss_score,
                            "cve": f.cve_id,
                            "url": f.evidence.get("url") if isinstance(f.evidence, dict) else None,
                        }
                        for f in findings
                    ],
                    "artifacts": [art.filename for art in artifacts],
                }
        except Exception as e:
            logger.error("Failed to load scan context: %s", e)
            return {}

    @classmethod
    def _synthesize_deterministic_response(cls, query: str, ctx: Dict[str, Any]) -> str:
        """Synthesize highly technical, helpful, context-rich responses deterministically."""
        q = query.lower()
        target = ctx.get("target", "target domain")
        findings = ctx.get("findings", [])
        assets = ctx.get("assets", [])
        ports = ctx.get("ports", [])
        artifacts = ctx.get("artifacts", [])

        # ── Case A: PoC Generation ─────────────────────────────────────────
        if any(w in q for w in ["poc", "exploit", "script", "payload", "python"]):
            target_finding = findings[0] if findings else {
                "title": "SQL Injection in Search Query Parameter",
                "severity": "CRITICAL",
                "url": f"https://{target}/search?q=payload",
            }
            url = target_finding.get("url") or f"https://{target}/api/v1/resource?id=1"
            return (
                f"### 🧪 Proof-of-Concept Exploit Script (Python 3)\n\n"
                f"Berikut adalah script PoC modular untuk memvalidasi temuan **{target_finding['title']}** pada `{target}`:\n\n"
                f"```python\n"
                f"import sys\n"
                f"import requests\n\n"
                f"# Konfigurasi Target\n"
                f"TARGET_URL = \"{url}\"\n"
                f"HEADERS = {{\n"
                f"    \"User-Agent\": \"HunterAja-Security-Audit/4.0 (+https://hunteraja.internal/audit)\",\n"
                f"    \"Accept\": \"application/json, text/html\",\n"
                f"}}\n"
                f"PROXIES = {{\"http\": \"http://127.0.0.1:8080\", \"https\": \"http://127.0.0.1:8080\"}} # Opsional Burp Suite\n\n"
                f"def test_vulnerability():\n"
                f"    print(f\"[*] Mengirim payload validasi ke: {{TARGET_URL}}\")\n"
                f"    try:\n"
                f"        # Safe canary payload\n"
                f"        payload = \"' OR '1'='1' -- -\"\n"
                f"        params = {{\"q\": payload, \"id\": \"1' AND 1=1-- -\"}}\n"
                f"        res = requests.get(TARGET_URL, params=params, headers=HEADERS, timeout=10, verify=False)\n\n"
                f"        print(f\"[+] Status Code: {{res.status_code}}\")\n"
                f"        print(f\"[+] Response Size: {{len(res.content)}} bytes\")\n\n"
                f"        # Deteksi bukti respons\n"
                f"        if res.status_code == 200 and (\"syntax error\" in res.text.lower() or len(res.text) > 500):\n"
                f"            print(\"[!] VULNERABLE: Respons server terindikasi rentan!\")\n"
                f"        else:\n"
                f"            print(\"[-] Response normal atau payload difilter WAF.\")\n"
                f"    except requests.RequestException as err:\n"
                f"        print(f\"[!] Request error: {{err}}\")\n\n"
                f"if __name__ == \"__main__\":\n"
                f"    test_vulnerability()\n"
                f"```\n\n"
                f"> **Catatan Keamanan:** Gunakan PoC ini hanya untuk keperluan verifikasi berizin pada target `{target}`."
            )

        # ── Case B: Remediation Patch ──────────────────────────────────────
        elif any(w in q for w in ["remediasi", "patch", "fix", "perbaikan", "code fix"]):
            return (
                f"### 🛡️ Rekomendasi Patch & Perbaikan Kode\n\n"
                f"Berikut adalah panduan perbaikan standar industri untuk mencegah celah keamanan pada `{target}`:\n\n"
                f"#### 1. PHP (Prepared Statement PDO)\n"
                f"```php\n"
                f"// ❌ SEBELUM (Rentan SQLi):\n"
                f"// $sql = \"SELECT * FROM users WHERE username = '\" . $_GET['user'] . \"'\";\n\n"
                f"// ✅ SESUDAH (Aman dengan Parameterized Query):\n"
                f"$stmt = $pdo->prepare('SELECT id, username, email FROM users WHERE username = :user');\n"
                f"$stmt->execute(['user' => $_GET['user']]);\n"
                f"$user = $stmt->fetch(PDO::FETCH_ASSOC);\n"
                f"```\n\n"
                f"#### 2. Node.js / Express (Sanitasi & Parameterized Queries)\n"
                f"```javascript\n"
                f"// ✅ Gunakan parameterized queries dengan pg / mysql2:\n"
                f"const result = await db.query(\n"
                f"  'SELECT id, username FROM users WHERE id = $1 AND tenant_id = $2',\n"
                f"  [req.params.id, req.user.tenantId]\n"
                f");\n"
                f"```\n\n"
                f"#### 3. Python (SQLAlchemy ORM / Raw Safe Query)\n"
                f"```python\n"
                f"# ✅ Selalu gunakan bind parameters:\n"
                f"query = select(User).where(User.username == param_username)\n"
                f"result = await session.execute(query)\n"
                f"```\n"
            )

        # ── Case C: Attack Vector & Parameter Analysis ─────────────────────
        elif any(w in q for w in ["vector", "vektor", "parameter", "analisis", "attack"]):
            findings_summary = ""
            if findings:
                def _fmt_conf(c):
                    if isinstance(c, (int, float)):
                        return f"{int(c * 100)}%"
                    return str(c or "CONFIRMED")
                findings_summary = "\n".join([f"- **{f['title']}** [{f['severity']}] (Confidence: {_fmt_conf(f.get('confidence'))})" for f in findings[:5]])
            else:
                findings_summary = "- Belum ada temuan berisiko tinggi yang terkonfirmasi pada sesi ini."

            ports_str = ", ".join(ports[:6]) if ports else "Port 80, 443"

            return (
                f"### 🎯 Analisis Attack Surface & Vektor Serang `{target}`\n\n"
                f"Berdasarkan pemetaan otomatis Level L4 Engine:\n\n"
                f"1. **Surface Exposure:**\n"
                f"   - **Aset Subdomain:** `{len(assets)}` host aktif terpetakan.\n"
                f"   - **Open Ports & Services:** `{ports_str}`\n"
                f"   - **Sensitivitas File/Artifact:** `{len(artifacts)}` file sensitif diperiksa.\n\n"
                f"2. **Vektor Serang Prioritas:**\n"
                f"{findings_summary}\n\n"
                f"3. **Rekomendasi Tahap Lanjutan:**\n"
                f"   - Lakukan pemeriksaan fuzzer parameter pada endpoint login & pencarian.\n"
                f"   - Pastikan header `Content-Security-Policy` dan `X-Frame-Options` diterapkan di seluruh subdomain.\n"
                f"   - Tinjau file backup atau staging yang terpapar publik."
            )

        # ── Case D: Summary / Executive Brief ──────────────────────────────
        else:
            crit_count = sum(1 for f in findings if (f.get("severity") or "").upper() == "CRITICAL")
            high_count = sum(1 for f in findings if (f.get("severity") or "").upper() == "HIGH")

            return (
                f"### 🤖 Hunter Aja Pentest AI Copilot\n\n"
                f"Saya siap membantu analisis keamanan pada target **`{target}`**.\n\n"
                f"📊 **Status Investigasi Saat Ini:**\n"
                f"- **Subdomain Aktif:** {len(assets)} host\n"
                f"- **Total Temuan:** {len(findings)} (🔴 {crit_count} Critical, 🟠 {high_count} High)\n"
                f"- **Open Ports:** {len(ports)} services\n\n"
                f"💡 **Anda dapat meminta saya untuk:**\n"
                f"1. 🧪 *\"Generate Python Exploit PoC untuk verifikasi temuan\"*\n"
                f"2. 🛡️ *\"Tampilkan contoh patch remediasi kode untuk developer\"*\n"
                f"3. 🎯 *\"Analisis vektor serang parameter paling rawan pada target ini\"*\n"
                f"4. 📄 *\"Buatkan ringkasan risiko eksekutif untuk laporan resmi\"*"
            )

    @classmethod
    def _get_suggested_actions(cls, query: str, findings: List[Dict[str, Any]]) -> List[str]:
        return [
            "🧪 Generate Python PoC",
            "🛡️ Tampilkan Patch Remediasi",
            "🎯 Analisis Attack Vector",
            "📊 Ringkasan Risiko Eksekutif",
        ]


pentest_copilot = PentestCopilot()
