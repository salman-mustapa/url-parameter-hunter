import datetime
import html
import io
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.reporting.poc_builder import PocBuilder
from app.reporting.redaction import RedactionEngine
from app.reporting.serializers import finding_quality



class ReportEngine:
    """Professional Report Generation Engine (§52, §100, §101).
    Produces audit-grade, sanitized security assessment reports in Markdown, HTML, JSON, and ready-to-use PDF.
    """

    @classmethod
    def _prepare_findings(cls, findings, perspective="customer"):
        result = []
        for original in findings:
            # Sanitize structured headers before converting them into strings
            # for replay commands or response excerpts.
            f = RedactionEngine.redact_dict(dict(original)) if perspective == "customer" else dict(original)
            evidence = dict(f.get("evidence") or {})
            for key in ("actual_result", "expected_result", "reproduction_steps", "preconditions"):
                if f.get(key):
                    evidence.setdefault(key, f[key])
            if f.get("poc"):
                evidence.setdefault("curl", f["poc"])
            f["evidence"] = evidence
            f["report_quality"] = finding_quality(f)
            f["poc_dossier"] = PocBuilder.generate_dossier(
                title=f.get("title") or "Finding", finding_type=f.get("finding_type") or "",
                severity=f.get("severity") or "INFO", target_url=f.get("location") or "",
                target_host=f.get("asset_hostname") or "", evidence=evidence,
                parameter=f.get("parameter"), cwe_id=f.get("cwe_id"), cve_id=f.get("cve_id"),
                cvss_score=f.get("cvss_score"), method=evidence.get("method", "GET"))
            result.append(f)
        return RedactionEngine.redact_dict(result) if perspective == "customer" else result

    @staticmethod
    def _format_report_time(value: Any, fallback: str) -> str:
        if not value:
            return fallback
        if hasattr(value, "isoformat"):
            return value.isoformat()
        return str(value)

    @staticmethod
    def _engagement_lines(stats):
        context = stats.get("report_context") or {}
        profile = context.get("report") or {}
        rules = context.get("rules") or {}
        def value(text):
            return str(text or "Not recorded").replace("\n", " ").replace("\r", " ").replace("`", "'")
        return [
            "## Engagement & Report Identity", "",
            *[f"- **{label}:** {value(profile.get(key))}" for label, key in (
                ("Organization", "organization"), ("Program / Engagement", "program"),
                ("Assessor", "assessor"), ("Asset", "asset_name"), ("Asset Type", "asset_type"),
                ("Application Version", "application_version"), ("Responsible Contact", "contact"))],
            f"- **Classification:** {value(profile.get('classification') or 'CONFIDENTIAL')}",
            f"- **Authorization Reference:** {value(context.get('authorization_reference'))}",
            f"- **Permitted Window:** {value(rules.get('starts_at'))} to {value(rules.get('ends_at'))}",
            f"- **Execution Window:** {value(context.get('started_at'))} to {value(context.get('completed_at'))}",
            f"- **Program Allowlist:** {value(', '.join(rules.get('scope_hosts') or []))}",
            f"- **Exclusions:** {value(', '.join(rules.get('excluded_hosts') or []))}",
            f"- **Allowed Ports:** {value(', '.join(str(port) for port in rules.get('allowed_ports') or []))}",
            f"- **Requested HTTP RPS Cap:** {value(rules.get('max_rps'))} (per-tool enforcement must be reviewed)",
            f"- **Platform:** {value(rules.get('platform'))}",
            f"- **Program Policy URL:** {value(rules.get('program_url'))}",
            f"- **Allowed Techniques:** {value(', '.join(rules.get('allowed_techniques') or []))}",
            f"- **Prohibited Techniques:** {value(', '.join(rules.get('prohibited_techniques') or []))}",
            f"- **Out-of-Scope Finding Types:** {value(', '.join(rules.get('out_of_scope_findings') or []))}",
            f"- **Profile / Level:** {value(context.get('profile'))} / {value(context.get('validation_level'))}",
            f"- **Program Notes:** {value(rules.get('notes'))}",
            f"- **Business Context:** {value(profile.get('executive_context'))}",
            "", "Recorded scope and authorization are operator-supplied; they are not independent evidence of permission.", "",
        ]

    @staticmethod
    def _ai_analysis_lines(stats):
        analysis = ((stats.get("report_context") or {}).get("ai_analysis") or {}).get("post_tools") or {}
        if not analysis:
            return []

        def clean(value):
            return str(value or "Not recorded").replace("\r", " ").replace("\n", " ").replace("`", "'")

        lines = [
            "## AI Evidence Review & Recommended Next Actions",
            "",
            "AI output is advisory. Scope policy and collected evidence remain authoritative.",
            "",
            f"**Evidence-bound summary:** {clean(analysis.get('executive_summary'))}",
            "",
        ]
        for label, key in (
            ("Coverage gaps", "coverage_gaps"),
            ("Recommended next tests", "recommended_next_tests"),
            ("Recommended techniques", "recommended_techniques"),
            ("Submission/review notes", "report_notes"),
        ):
            values = analysis.get(key) or []
            lines.append(f"### {label}")
            lines.extend(f"- {clean(item)}" for item in values)
            if not values:
                lines.append("- None recorded; manual review is still required.")
            lines.append("")
        return lines

    @staticmethod
    def _technology_candidates(technologies):
        from app.intelligence.cve import CveIntelligence
        return [{"technology": t.get("name"), "version": t.get("version"), **candidate}
                for t in technologies[:200] if t.get("name")
                for candidate in CveIntelligence.match_candidates(t["name"], t.get("version"))]

    @classmethod
    def generate_markdown(
        cls,
        scan_id: str,
        target: str,
        stats: Dict[str, Any],
        findings: List[Dict[str, Any]],
        assets: List[Dict[str, Any]],
        ports: List[Dict[str, Any]],
        technologies: List[Dict[str, Any]],
        operator: Optional[str] = None,
        view_perspective: str = "customer",
    ) -> str:
        date_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        redacted_findings = cls._prepare_findings(findings, view_perspective)
        profile = (stats.get("report_context") or {}).get("report") or {}

        lines = [
            f"# 🛡️ Security Assessment & Bug Hunting Report",
            f"",
            f"**Target Scope:** `{target}`  ",
            f"**Scan ID:** `{scan_id}`  ",
            f"**Date Generated:** `{date_str}`  ",
            f"**Assessor / Operator:** `{profile.get('assessor') or operator or 'Not recorded'}`  ",
            f"**Classification:** `{profile.get('classification') or 'CONFIDENTIAL'}`  ",
            f"",
            f"---",
            f"",
            f"## 1. Executive Summary",
            f"",
            f"This report summarizes stored assessment records for `{target}`.",
            f"Review scan execution logs, authorization and evidence completeness before relying on these results.",
            f"",
            f"| Metric | Total Discovered |",
            f"|---|---|",
            f"| **Subdomains & Assets** | {stats.get('total_assets', len(assets))} |",
            f"| **Open Ports & Services** | {stats.get('total_ports', len(ports))} |",
            f"| **Discovered URLs / Endpoints** | {stats.get('total_urls', 0)} |",
            f"| **Identified Technologies** | {stats.get('total_technologies', len(technologies))} |",
            f"| **Recorded Security Findings** | **{len(findings)}** |",
            f"",
            f"---",
            f"",
            f"## 2. Scope & Authorization Boundary (§102)",
            f"",
            f"- **Recorded Target:** `{target}`",
            f"- **Methodology:** Profile-dependent checks; consult the execution log for checks actually completed.",
            f"- **Rate Limit:** Consult scan configuration and execution logs; this report does not independently verify rate-limit enforcement.",
            f"",
            f"---",
            f"",
            f"## 3. Attack Surface & Technology Inventory",
            f"",
            f"### Identified Technologies",
        ]

        if technologies:
            for t in technologies[:20]:
                ver = f" (v{t.get('version')})" if t.get("version") else ""
                lines.append(f"- **{t.get('name')}**{ver} on `{t.get('hostname', target)}`")
        else:
            lines.append("_No specialized technologies detected._")

        lines.extend([
            f"",
            f"---",
            f"",
            f"## 4. Recorded Security Findings & Proof of Concept (§52, §101)",
            f"",
        ])

        if not redacted_findings:
            lines.append("✅ **No Findings Recorded** — No findings are recorded. This does not establish that the target is secure or that test coverage is complete.")
        else:
            for i, f in enumerate(redacted_findings, 1):
                code = f.get("finding_code") or f"BH-2026-{i:03d}"
                sev = f.get("severity", "INFO").upper()
                cwe = f" ({f.get('cwe_id')})" if f.get("cwe_id") else ""
                cvss = f" [CVSS {f.get('cvss_score')}]" if f.get("cvss_score") else ""
                loc = f.get("location") or f.get("url") or "Not recorded"
                poc = f.get("poc") or f.get("poc_curl") or f.get("curl_command") or f"curl -s -k -X GET '{loc}'"
                tech_details = f.get("technical_details") or "Technical observations not recorded."
                evidence_info = f.get("evidence")

                found_at = cls._format_report_time(f.get("first_seen"), "Not recorded")
                confirmed_at = cls._format_report_time(f.get("last_seen"), "Not recorded")

                lines.extend([
                    f"### {code}: [{sev}] {f.get('title')}{cwe}{cvss}",
                    f"",
                    f"- **Status:** `{f.get('status') or 'NOT_RECORDED'}`",
                    f"- **Confidence:** `{f.get('confidence') or 'INCONCLUSIVE'}`",
                    f"- **Asset Location:** `{f.get('asset_hostname') or target}`",
                    f"- **Endpoint / Parameter:** `{loc}`",
                    f"- **Discovery Timeline:** First seen: `{found_at}` | Last updated: `{confirmed_at}`",
                    f"- **Evidence Level:** `{f.get('evidence_level') or 'E0'}`",
                    f"- **Report Readiness:** `{f['report_quality']['status']}`",
                    f"- **Missing Evidence / Context:** {', '.join(f['report_quality']['missing']) or 'None in completeness check; human review still required.'}",
                    "- **Reproduction note:** Generated replay templates are not proof that a vulnerability was reproduced.",
                    f"",
                    f"#### 1. Summary",
                    f"{f.get('executive_explanation') or f.get('summary') or f.get('description') or 'Summary not recorded.'}",
                    f"",
                    f"#### 2. Description & Mechanism",
                    f"{f.get('description') or 'Description not recorded.'}",
                    f"",
                    f"#### 3. Risk & Business Impact",
                    f"{f.get('business_impact') or f.get('impact') or 'Impact not recorded.'}",
                    f"- **CVSS Version / Vector:** {f.get('cvss_version') or 'Not recorded'} / {f.get('cvss_vector') or 'Not recorded'}",
                    f"- **CVE Applicability:** {f.get('cve_match_status') or 'Not assessed'}; product, version range and configuration require validation.",
                    f"- **Impact Dimensions (CIA):** {json.dumps(f.get('impact_matrix') or {}, ensure_ascii=False)}",
                    f"",
                ])

                # Root cause analysis
                root_cause = f.get("root_cause")
                rc_text = root_cause if isinstance(root_cause, str) else (root_cause.get("explanation", str(root_cause)) if root_cause else "Root cause not established.")
                lines.extend([
                    f"#### 4. Root Cause Analysis",
                    f"{rc_text}",
                    f"",
                ])

                # Complete Bug Bounty Proof of Concept (PoC) Dossier
                dossier = f.get("poc_dossier")
                if not dossier:
                    dossier = PocBuilder.generate_dossier(
                        title=f.get("title", "Finding"),
                        finding_type=f.get("finding_type") or f.get("title", ""),
                        severity=sev,
                        target_url=loc,
                        target_host=f.get("asset_hostname") or target,
                        parameter=f.get("parameter"),
                        method=f.get("method", "GET"),
                        payload=f.get("payload"),
                        cwe_id=f.get("cwe_id"),
                        cve_id=f.get("cve_id"),
                        cvss_score=f.get("cvss_score"),
                        description=f.get("description"),
                        technical_details=tech_details,
                        evidence=evidence_info if isinstance(evidence_info, dict) else {},
                        has_real_screenshot=bool(f.get("screenshot_path") and os.path.exists(f.get("screenshot_path"))),
                        screenshot_url=f.get("screenshot_url") or f.get("screenshot_path"),
                    )

                repro_steps_list = dossier.get("reproduction_steps") or f.get("reproduction_steps") or []
                repro_steps_rendered = "\n".join(f"{s_idx}. {step}" for s_idx, step in enumerate(repro_steps_list, 1))

                ss_info = dossier.get("screenshot", {})
                if ss_info.get("has_screenshot") and ss_info.get("image_url"):
                    screenshot_block = f"**Visual Evidence (Real Browser Screenshot):**\n![Visual Proof Capture]({ss_info['image_url']})\n_{ss_info.get('caption', 'Live automated browser capture')}_\n"
                else:
                    screenshot_block = f"**Visual Evidence Status:**\n> {ss_info.get('explanation_if_none', 'Visual screenshot not applicable for this API finding. Wire-level HTTP response proof is documented below.')}\n"

                lines.extend([
                    f"#### 5. Reproduction Steps & Proof of Concept (PoC) Dossier",
                    f"",
                    f"**Step-by-Step Manual Reproduction Guide:**",
                    f"{repro_steps_rendered}",
                    f"",
                    f"**Python Replay Template (Not Executed):**",

                    f"```python",
                    f"{dossier.get('python_poc', '')}",
                    f"```",
                    f"",
                    f"**cURL CLI Reproduction Command:**",
                    f"```bash",
                    f"{dossier.get('curl_command', poc)}",
                    f"```",
                    f"",
                    f"**Wire-Level HTTP Request Proof:**",
                    f"```http",
                    f"{dossier.get('raw_http_request', '')}",
                    f"```",
                    f"",
                    f"**Recorded HTTP Response / Missing Evidence:**",
                    f"```http",
                    f"{dossier.get('raw_http_response', '')}",
                    f"```",
                    f"",
                    f"{screenshot_block}",
                    f"**Behavioral Contrast:**",
                    f"- **Expected Secure Behavior:** {dossier.get('expected_behavior', '')}",
                    f"- **Actual Observed Behavior:** {dossier.get('actual_behavior', '')}",
                    f"",
                ])

                if evidence_info and isinstance(evidence_info, dict):
                    ev_str = json.dumps(evidence_info, indent=2, default=str) if evidence_info else ""
                    if ev_str and ev_str != "{}":
                        lines.extend([
                            f"**Raw Metadata Evidence Artifact:**",
                            f"```json",
                            f"{ev_str}",
                            f"```",
                            f"",
                        ])


                # Exploitation Evidence (Deep Proof)
                exploitation_data = f.get("exploitation_data") or f.get("evidence", {}).get("exploitation_data")
                if exploitation_data and isinstance(exploitation_data, dict):
                    attack_type = f.get("attack_type", f.get("vulnerability_type", ""))

                    if attack_type == "sqli" and exploitation_data.get("database_name"):
                        lines.extend([
                            f"#### 📊 Database Exploitation Evidence (Server-Side Proof)",
                            f"",
                            f"| Property | Value |",
                            f"|---|---|",
                            f"| **Database Name** | `{exploitation_data.get('database_name', 'N/A')}` |",
                            f"| **Database User** | `{exploitation_data.get('database_user', 'N/A')}` |",
                            f"| **Database Version** | `{exploitation_data.get('database_version', 'N/A')}` |",
                            f"| **UNION Column Count** | `{exploitation_data.get('column_count', 'N/A')}` |",
                            f"",
                        ])
                        tables = exploitation_data.get("tables", [])
                        if tables:
                            lines.append(f"**Extracted Tables ({len(tables)}):**")
                            for tbl in tables[:10]:
                                row_counts = exploitation_data.get("row_counts", {})
                                count_str = f" — {row_counts[tbl]:,} rows" if tbl in row_counts else ""
                                lines.append(f"- `{tbl}`{count_str}")
                            lines.append("")

                        columns = exploitation_data.get("columns", {})
                        if columns:
                            lines.append(f"**Extracted Columns per Table:**")
                            for tbl, cols in list(columns.items())[:5]:
                                cols_str = ", ".join(f"`{c}`" for c in cols[:10])
                                lines.append(f"- **{tbl}**: {cols_str}")
                            lines.append("")

                    elif attack_type == "upload":
                        lines.extend([
                            f"#### 📦 File Upload & Script Execution Evidence",
                            f"",
                            f"| Property | Value |",
                            f"|---|---|",
                            f"| **Execution Confirmed** | `{exploitation_data.get('rce_confirmed', 'Not recorded')}` |",
                            f"| **Uploaded Canary URL** | `{exploitation_data.get('uploaded_url', 'N/A')}` |",
                            f"| **Canary Validation Hash** | `{exploitation_data.get('canary_hash', 'N/A')}` |",
                            f"| **Execution Proof** | `{exploitation_data.get('execution_proof', 'Not recorded')}` |",
                            f"",
                        ])

                    elif attack_type == "rce":
                        cmd_outputs = exploitation_data.get("command_outputs", {})
                        lines.extend([
                            f"#### 💻 System Exploitation Evidence (Command Execution Proof)",
                            f"",
                            f"| Property | Value |",
                            f"|---|---|",
                            f"| **Current User** | `{exploitation_data.get('current_user', exploitation_data.get('username', 'N/A'))}` |",
                            f"| **Hostname** | `{exploitation_data.get('hostname', 'N/A')}` |",
                            f"| **Kernel Info** | `{exploitation_data.get('kernel_info', 'N/A')}` |",
                            f"| **UID/GID** | `uid={exploitation_data.get('uid', '?')} gid={exploitation_data.get('gid', '?')}` |",
                            f"| **Privilege Level** | `{exploitation_data.get('privilege_level', 'N/A')}` |",
                            f"| **Privileged Groups** | `{', '.join(exploitation_data.get('privileged_groups', []))}` |",
                            f"| **Commands Executed** | `{exploitation_data.get('commands_executed', 0)}` |",
                            f"",
                        ])
                        if cmd_outputs.get("id_output"):
                            lines.extend([
                                f"**`id` output:**",
                                f"```",
                                f"{cmd_outputs['id_output'][:500]}",
                                f"```",
                                f"",
                            ])
                        if cmd_outputs.get("passwd_output") or exploitation_data.get("passwd_content"):
                            passwd = cmd_outputs.get("passwd_output") or exploitation_data.get("passwd_content", "")
                            lines.extend([
                                f"**`cat /etc/passwd` output ({exploitation_data.get('passwd_entries', '?')} entries):**",
                                f"```",
                                f"{passwd[:2000]}",
                                f"```",
                                f"",
                            ])
                        real_users = exploitation_data.get("real_users", [])
                        if real_users:
                            lines.extend([
                                f"**Real User Accounts (uid ≥ 1000):**",
                                f"| Username | UID | Home | Shell |",
                                f"|---|---|---|---|",
                            ])
                            for u in real_users[:10]:
                                lines.append(f"| `{u.get('username')}` | {u.get('uid')} | `{u.get('home')}` | `{u.get('shell')}` |")
                            lines.append("")

                    elif attack_type == "xss":
                        lines.extend([
                            f"#### 🌐 XSS Exploitation Evidence (Browser Context Proof)",
                            f"",
                            f"| Property | Value |",
                            f"|---|---|",
                            f"| **Payload Intact in DOM** | `{exploitation_data.get('payload_intact_in_dom', False)}` |",
                            f"| **Session Hijack Risk** | `{exploitation_data.get('session_hijack_risk', 'N/A')}` |",
                            f"| **Verified Payloads** | `{exploitation_data.get('verified_payloads_count', 0)}` |",
                            f"",
                        ])
                        csp = exploitation_data.get("csp_analysis", {})
                        if csp:
                            csp_status = "ABSENT" if not csp.get("csp_present") else (
                                "Allows unsafe-inline" if csp.get("allows_unsafe_inline") else "Enforced"
                            )
                            lines.extend([
                                f"**CSP Analysis:**",
                                f"- CSP Present: `{csp.get('csp_present', False)}`",
                                f"- Status: `{csp_status}`",
                                f"- XSS Blocked by CSP: `{csp.get('xss_blocked_by_csp', False)}`",
                                f"",
                            ])
                        cookie = exploitation_data.get("cookie_analysis", {})
                        if cookie and cookie.get("cookies_without_httponly"):
                            lines.extend([
                                f"**Cookie Security:**",
                                f"- Cookies without HttpOnly: `{', '.join(cookie['cookies_without_httponly'])}`",
                                f"- Session cookies accessible via JavaScript: **YES — session hijack possible**",
                                f"",
                            ])
                        dom_context = exploitation_data.get("dom_context_sample", "")
                        if dom_context:
                            lines.extend([
                                f"**DOM Context (payload reflection):**",
                                f"```html",
                                f"{dom_context[:500]}",
                                f"```",
                                f"",
                            ])

                    elif attack_type == "idor":
                        lines.extend([
                            f"#### 🔓 IDOR Exploitation Evidence (Multi-Object Access Proof)",
                            f"",
                            f"| Property | Value |",
                            f"|---|---|",
                            f"| **Total Objects Accessible** | `{exploitation_data.get('total_accessible', 0)}` |",
                            f"| **Unique Objects** | `{exploitation_data.get('unique_objects', 0)}` |",
                            f"| **Authorization Bypass** | `{exploitation_data.get('authorization_bypass_confirmed', False)}` |",
                            f"| **Sensitive Fields Exposed** | `{', '.join(exploitation_data.get('sensitive_fields_exposed', []))}` |",
                            f"",
                        ])
                        accessible = exploitation_data.get("accessible_objects", [])
                        if accessible:
                            lines.extend([
                                f"**Accessed Objects:**",
                                f"| Object ID | HTTP Status | Size | Sensitive Fields |",
                                f"|---|---|---|---|",
                            ])
                            for obj in accessible[:5]:
                                sens = ", ".join(obj.get("sensitive_fields", [])) or "—"
                                lines.append(f"| `{obj.get('id')}` | {obj.get('status')} | {obj.get('content_length', '?')} bytes | {sens} |")
                            lines.append("")

                    elif attack_type in ("traversal", "path_traversal") and exploitation_data.get("files_read"):
                        files_read = exploitation_data.get("files_read", {})
                        lines.extend([
                            f"#### 📂 Path Traversal / LFI Exploitation Evidence (File Read Proof)",
                            f"",
                            f"| Property | Value |",
                            f"|---|---|",
                            f"| **Exploitation Type** | `{exploitation_data.get('exploitation_type', 'local_file_inclusion')}` |",
                            f"| **Files Read** | `{exploitation_data.get('files_read_count', len(files_read))}` |",
                            f"| **OS Type** | `{exploitation_data.get('os_type', 'unknown')}` |",
                            f"| **Hostname** | `{exploitation_data.get('hostname', 'N/A')}` |",
                            f"| **Kernel** | `{exploitation_data.get('kernel', 'N/A')}` |",
                            f"| **OS** | `{exploitation_data.get('os_pretty_name', 'N/A')}` |",
                            f"| **Shadow Readable** | `{exploitation_data.get('shadow_accessible', False)}` |",
                            f"",
                        ])

                        # /etc/passwd content
                        passwd = exploitation_data.get("passwd_content", "")
                        if passwd:
                            lines.extend([
                                f"**`/etc/passwd` ({exploitation_data.get('passwd_entries', '?')} entries):**",
                                f"```",
                                f"{passwd[:2500]}",
                                f"```",
                                f"",
                            ])

                        # Real users table
                        real_users = exploitation_data.get("real_users", [])
                        if real_users:
                            lines.extend([
                                f"**Real User Accounts (uid ≥ 1000):**",
                                f"| Username | UID | GID | Home | Shell |",
                                f"|---|---|---|---|---|",
                            ])
                            for u in real_users[:15]:
                                lines.append(f"| `{u.get('username')}` | {u.get('uid')} | {u.get('gid', '?')} | `{u.get('home')}` | `{u.get('shell')}` |")
                            lines.append("")

                        # .env keys exposed
                        env_keys = exploitation_data.get("env_keys_exposed", [])
                        if env_keys:
                            keys_str = ", ".join(f"`{k}`" for k in env_keys[:15])
                            lines.extend([
                                f"**⚠️ .env File Keys Exposed:**",
                                f"{keys_str}",
                                f"",
                            ])

                        # Files read summary
                        if files_read:
                            lines.extend([
                                f"**Files Successfully Read:**",
                                f"| File | Size |",
                                f"|---|---|",
                            ])
                            for key, info in list(files_read.items())[:10]:
                                lines.append(f"| `{info.get('file', key)}` | {info.get('size', '?')} bytes |")
                            lines.append("")

                # Remediation (§21) & References
                cwe_id = f.get('cwe_id')
                cve_id = f.get('cve_id')
                ref_links = []
                if cwe_id:
                    digits = "".join(filter(str.isdigit, cwe_id))
                    if digits:
                        ref_links.append(f"[Mitre CWE-{digits}](https://cwe.mitre.org/data/definitions/{digits}.html)")
                if cve_id:
                    ref_links.append(f"[NVD {cve_id}](https://nvd.nist.gov/vuln/detail/{cve_id})")
                ref_str = ", ".join(ref_links) if ref_links else "No external references mapped."

                lines.extend([
                    f"#### 6. Remediation & Engineering Fixes",
                    f"{f.get('remediation') or 'Remediation not recorded.'}",
                    f"",
                    f"- **References:** {ref_str}",
                    f"- **Retest Status:** `{f.get('retest_status', 'PENDING')}`",
                    f"",
                    f"---",
                    f"",
                ])

        lines.extend([
            f"## 5. Methodology & Safety Statement",
            f"",
            f"The report summarizes stored records only. Review authorization, scan profile and execution logs to establish what was tested.",
            f"Missing findings or evidence do not prove absence of vulnerabilities. Generated replay examples require review before execution.",
            f"",
            f"_Report generated autonomously by Hunter Aja Advanced Security Intelligence Platform — Confidential Audit Record._",
        ])

        summary = ["## Finding Register & Review Priorities", "",
                   "Severity is recorded, not independently recalculated. Prioritize validated impact and owner review; missing evidence is not proof.", "",
                   "| ID | Severity | Finding | Evidence | Readiness |", "|---|---|---|---|---|"]
        for f in sorted(redacted_findings, key=lambda row: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(row.get("severity")) if row.get("severity") in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] else 5):
            values = [f.get("finding_code") or f.get("id") or "Unassigned", f.get("severity"), f.get("title"), f.get("evidence_level") or "E0", f["report_quality"]["status"]]
            summary.append("| " + " | ".join(str(v or "Not recorded").replace("|", "/").replace("\n", " ") for v in values) + " |")
        insert = lines.index("## 1. Executive Summary")
        lines[insert:insert] = cls._engagement_lines(stats)
        insert = lines.index("## 3. Attack Surface & Technology Inventory")
        lines[insert:insert] = summary + [""]
        ai_lines = cls._ai_analysis_lines(stats)
        if ai_lines:
            insert = lines.index("## 5. Methodology & Safety Statement")
            lines[insert:insert] = ai_lines + ["---", ""]
        candidates = cls._technology_candidates(technologies)
        if candidates:
            lines.extend(["", "## Appendix: CVE Research Candidates", "",
                          "Offline catalog suggestions only. Verify vendor advisories, component/version, configuration and prerequisites. No exploitation or current catalog freshness is asserted.", ""])
            for candidate in candidates[:100]:
                lines.append(f"- {candidate['cve_id']} | {candidate['technology']} {candidate.get('version') or 'version unknown'} | {candidate['match_status']} | https://nvd.nist.gov/vuln/detail/{candidate['cve_id']}")
            if len(candidates) > 100:
                lines.append(f"Showing 100 of {len(candidates)} candidates; the JSON report contains the complete candidate list for the first 200 technologies.")
        return "\n".join(lines)

    @classmethod
    def generate_json(
        cls,
        scan_id: str,
        target: str,
        stats: Dict[str, Any],
        findings: List[Dict[str, Any]],
        assets: List[Dict[str, Any]],
        ports: List[Dict[str, Any]],
        technologies: List[Dict[str, Any]],
        operator: Optional[str] = None,
        view_perspective: str = "customer",
    ) -> str:
        """Render complete sanitized JSON dataset for SIEM/SOAR/automation ingestion."""
        date_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        redacted_findings = cls._prepare_findings(findings, view_perspective)
        profile = (stats.get("report_context") or {}).get("report") or {}
        data = {
            "report_metadata": {
                "scan_id": scan_id,
                "target": target,
                "generated_at": date_str,
                "operator": profile.get("assessor") or operator,
                "classification": profile.get("classification") or "CONFIDENTIAL",
                "version": "8.0.0",
                "engagement": stats.get("report_context") or {},
            },
            "summary": {
                "total_assets": stats.get("total_assets", len(assets)),
                "total_ports": stats.get("total_ports", len(ports)),
                "total_urls": stats.get("total_urls", 0),
                "total_technologies": stats.get("total_technologies", len(technologies)),
                "total_findings": len(findings),
            },
            "findings": redacted_findings,
            "assets": assets,
            "ports": ports,
            "technologies": technologies,
            "cve_research_candidates": cls._technology_candidates(technologies),
        }
        return json.dumps(data, indent=2, default=str)

    @classmethod
    def generate_html(
        cls,
        scan_id: str,
        target: str,
        stats: Dict[str, Any],
        findings: List[Dict[str, Any]],
        assets: List[Dict[str, Any]],
        ports: List[Dict[str, Any]],
        technologies: List[Dict[str, Any]],
        operator: Optional[str] = None,
    ) -> str:
        """Render executive HTML report with responsive styling and print/PDF optimization."""
        date_str = datetime.datetime.now(datetime.timezone.utc).strftime("%d %B %Y, %H:%M:%S UTC")
        redacted_findings = cls._prepare_findings(findings)
        profile = (stats.get("report_context") or {}).get("report") or {}
        identity_html = "<section>" + "".join(f"<p>{html.escape(line.lstrip('# ').removeprefix('- ').replace('**', ''))}</p>" for line in (cls._engagement_lines(stats) + cls._ai_analysis_lines(stats)) if line) + "</section>"
        logo = profile.get("logo_data_url") or ""
        logo_html = f'<img alt="Organization logo supplied by operator" src="{html.escape(logo)}" style="max-width:220px;max-height:90px;object-fit:contain">' if logo.startswith("data:image/png;base64,") else ""

        total_assets = stats.get('total_assets', len(assets))
        total_ports = stats.get('total_ports', len(ports))
        total_urls = stats.get('total_urls', 0)
        total_tech = stats.get('total_technologies', len(technologies))

        findings_html = ""
        if not redacted_findings:
            findings_html = """
            <div class="clean-state-box">
                <span class="clean-icon">✅</span>
                <div>
                    <h3>No Findings Recorded</h3>
                    <p>No findings are recorded. This does not establish that the target is secure or test coverage complete.</p>
                </div>
            </div>
            """
        else:
            for idx, f in enumerate(redacted_findings, 1):
                code = html.escape(str(f.get("finding_code") or f"BH-2026-{idx:03d}"))
                sev = html.escape(str(f.get("severity", "INFO")).upper())
                title = html.escape(str(f.get("title", "Finding")))
                cwe = f" ({html.escape(f['cwe_id'])})" if f.get("cwe_id") else ""
                cvss = f" [CVSS {html.escape(str(f['cvss_score']))}]" if f.get("cvss_score") else ""
                desc = html.escape(str(f.get("description", "No description.")))
                impact = html.escape(str(f.get("impact") or "Impact not recorded."))
                tech = html.escape(str(f.get("technical_details") or "Validation details not recorded."))
                rem = html.escape(str(f.get("remediation") or "Remediation not recorded."))
                loc = html.escape(str(f.get("location") or f.get("url") or f.get("asset_hostname") or target))
                status = html.escape(str(f.get("status") or "NOT_RECORDED"))
                conf = html.escape(str(f.get("confidence") or "INCONCLUSIVE"))

                # PoC Dossier
                dossier = f.get("poc_dossier")
                if not dossier:
                    dossier = PocBuilder.generate_dossier(
                        title=f.get("title", "Finding"),
                        finding_type=f.get("finding_type") or f.get("title", ""),
                        severity=sev,
                        target_url=loc,
                        target_host=f.get("asset_hostname") or target,
                        parameter=f.get("parameter"),
                        method=f.get("method", "GET"),
                        payload=f.get("payload"),
                        cwe_id=f.get("cwe_id"),
                        cve_id=f.get("cve_id"),
                        cvss_score=f.get("cvss_score"),
                        description=f.get("description"),
                        technical_details=f.get("technical_details"),
                        evidence=f.get("evidence") if isinstance(f.get("evidence"), dict) else {},
                        has_real_screenshot=bool(f.get("screenshot_path") and os.path.exists(f.get("screenshot_path"))),
                        screenshot_url=f.get("screenshot_url") or f.get("screenshot_path"),
                    )

                repro_steps_html = "".join(f"<li>{html.escape(s)}</li>" for s in (dossier.get("reproduction_steps") or []))

                ss_info = dossier.get("screenshot", {})
                if ss_info.get("has_screenshot") and ss_info.get("image_url"):
                    screenshot_html = f"""
                    <div class="finding-section">
                        <strong>📸 Visual Evidence (Real Browser Screenshot):</strong>
                        <div style="margin-top: 8px; border: 1px solid var(--border); border-radius: 6px; overflow: hidden; max-width: 600px;">
                            <img src="{html.escape(ss_info['image_url'])}" alt="Visual Proof Capture" style="width: 100%; height: auto; display: block;">
                        </div>
                        <div style="font-size: 0.75rem; color: var(--text-secondary); margin-top: 4px;">{html.escape(ss_info.get('caption', ''))}</div>
                    </div>
                    """
                else:
                    screenshot_html = f"""
                    <div class="finding-section" style="background: rgba(255,255,255,0.03); padding: 10px; border-radius: 6px; border-left: 3px solid #64748b;">
                        <strong style="color: var(--text-secondary);">📸 Visual Proof Status:</strong>
                        <p style="margin: 4px 0 0 0; font-size: 0.8rem; color: #94a3b8;">{html.escape(ss_info.get('explanation_if_none', 'Visual screenshot not applicable for this API finding.'))}</p>
                    </div>
                    """

                evidence_block = ""
                if f.get("evidence") and isinstance(f.get("evidence"), dict) and f.get("evidence") != {}:
                    evidence_block = f"""
                    <div class="finding-section">
                        <strong>Sanitized Raw Evidence Artifact:</strong>
                        <pre class="evidence-box"><code>{html.escape(json.dumps(f.get("evidence"), indent=2, default=str))}</code></pre>
                    </div>
                    """

                findings_html += f"""
                <div class="finding-block severity-{sev.lower()}">
                    <div class="finding-header">
                        <span class="severity-tag tag-{sev.lower()}">{sev}</span>
                        <h4>{code}: {title}{cwe}{cvss}</h4><p><strong>Report readiness:</strong> {html.escape(f["report_quality"]["status"])} | Missing: {html.escape(", ".join(f["report_quality"]["missing"]) or "Human review still required")}</p>
                    </div>
                    <div class="finding-meta">
                        <span><strong>Asset:</strong> <code>{html.escape(f.get('asset_hostname') or target)}</code></span>
                        <span><strong>Endpoint:</strong> <code>{loc}</code></span>
                        <span><strong>Status:</strong> <span class="badge">{status}</span></span>
                        <span><strong>Confidence:</strong> <span class="badge">{conf}</span></span>
                    </div>
                    <div class="finding-section">
                        <strong>Description:</strong>
                        <p>{desc}</p>
                    </div>
                    <div class="finding-section">
                        <strong>Impact:</strong>
                        <p>{impact}</p>
                    </div>
                    <div class="finding-section">
                        <strong>Technical Details:</strong>
                        <p>{tech}</p>
                    </div>
                    <div class="finding-section poc">
                        <strong>1. Step-by-Step Manual Reproduction Guide:</strong>
                        <ol style="padding-left: 20px; margin-top: 6px; line-height: 1.6;">
                            {repro_steps_html}
                        </ol>
                    </div>
                    <div class="finding-section poc">
                        <strong>2. Python Replay Template (Not Executed):</strong>
                        <pre class="poc-box"><code class="language-python">{html.escape(dossier.get('python_poc', ''))}</code></pre>
                    </div>
                    <div class="finding-section poc">
                        <strong>3. cURL CLI Reproduction:</strong>
                        <pre class="poc-box"><code>{html.escape(dossier.get('curl_command', ''))}</code></pre>
                    </div>
                    <div class="finding-section poc">
                        <strong>4. Wire-Level HTTP Request:</strong>
                        <pre class="poc-box"><code>{html.escape(dossier.get('raw_http_request', ''))}</code></pre>
                    </div>
                    <div class="finding-section poc">
                        <strong>5. Recorded HTTP Response / Missing Evidence:</strong>
                        <pre class="poc-box"><code>{html.escape(dossier.get('raw_http_response', ''))}</code></pre>
                    </div>
                    {screenshot_html}
                    <div class="finding-section" style="background: rgba(0,0,0,0.3); padding: 10px; border-radius: 6px; margin-top: 10px;">
                        <div><strong>Expected Secure Behavior:</strong> <span style="color: #4ade80;">{html.escape(dossier.get('expected_behavior', ''))}</span></div>
                        <div style="margin-top: 6px;"><strong>Recorded Actual Behavior:</strong> <span style="color: #f87171;">{html.escape(dossier.get('actual_behavior', ''))}</span></div>
                    </div>
                    {evidence_block}
                    <div class="finding-section remediation">
                        <strong>Remediation Playbook:</strong>
                        <p>{rem}</p>
                    </div>
                    <div class="finding-meta" style="margin-top: 10px; margin-bottom: 0;">
                        <span><strong>Retest Status:</strong> <code>{html.escape(str(f.get('retest_status', 'PENDING')))}</code></span>
                    </div>
                </div>
                """


        tech_items = "".join(
            f"<li><strong>{html.escape(t.get('name', ''))}</strong>{' (v' + html.escape(str(t.get('version'))) + ')' if t.get('version') else ''} on <code>{html.escape(t.get('hostname', target))}</code></li>"
            for t in technologies[:20]
        ) or "<li><em>No specialized technologies detected.</em></li>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report — {html.escape(target)}</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #0d1117;
            --card-bg: #161b22;
            --border: #30363d;
            --text-primary: #f0f6fc;
            --text-secondary: #8b949e;
            --accent: #58a6ff;
            --critical: #f85149;
            --high: #f0883e;
            --medium: #d29922;
            --low: #58a6ff;
            --info: #8b949e;
            --clean: #3fb950;
        }}
        @media print {{
            body {{ background: #fff !important; color: #000 !important; }}
            .report-container {{ max-width: 100% !important; box-shadow: none !important; border: none !important; }}
            .finding-block {{ break-inside: avoid; }}
            .print-btn-bar {{ display: none !important; }}
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg);
            color: var(--text-primary);
            font-family: 'Plus Jakarta Sans', sans-serif;
            line-height: 1.6;
            padding: 40px 20px;
        }}
        .report-container {{
            max-width: 960px;
            margin: 0 auto;
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 36px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.5);
        }}
        .report-header {{
            border-bottom: 1px solid var(--border);
            padding-bottom: 24px;
            margin-bottom: 32px;
        }}
        .report-title {{
            font-size: 1.7rem;
            font-weight: 800;
            margin-bottom: 12px;
        }}
        .report-meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 12px;
            font-size: 0.88rem;
            color: var(--text-secondary);
        }}
        .report-meta-grid strong {{ color: var(--text-primary); }}
        h2 {{
            font-size: 1.25rem;
            font-weight: 700;
            margin: 28px 0 16px;
            padding-bottom: 8px;
            border-bottom: 1px solid var(--border);
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 10px;
            margin-bottom: 24px;
        }}
        .summary-card {{
            background: rgba(255,255,255,0.03);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px;
            text-align: center;
        }}
        .summary-val {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 1.5rem;
            font-weight: 800;
            color: var(--accent);
        }}
        .summary-label {{
            font-size: 0.72rem;
            text-transform: uppercase;
            color: var(--text-secondary);
            margin-top: 4px;
        }}
        .finding-block {{
            background: rgba(0,0,0,0.25);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 18px;
            margin-bottom: 16px;
            border-left: 4px solid var(--accent);
        }}
        .finding-block.severity-critical {{ border-left-color: var(--critical); }}
        .finding-block.severity-high {{ border-left-color: var(--high); }}
        .finding-block.severity-medium {{ border-left-color: var(--medium); }}
        .finding-block.severity-low {{ border-left-color: var(--low); }}
        .finding-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 10px;
        }}
        .severity-tag {{
            font-size: 0.7rem;
            font-weight: 800;
            padding: 3px 8px;
            border-radius: 4px;
            text-transform: uppercase;
        }}
        .tag-critical {{ background: rgba(248,81,73,0.2); color: var(--critical); }}
        .tag-high {{ background: rgba(240,136,62,0.2); color: var(--high); }}
        .tag-medium {{ background: rgba(210,153,34,0.2); color: var(--medium); }}
        .tag-low {{ background: rgba(88,166,255,0.2); color: var(--low); }}
        .tag-info {{ background: rgba(139,148,158,0.2); color: var(--info); }}
        .finding-meta {{
            font-size: 0.85rem;
            color: var(--text-secondary);
            margin-bottom: 12px;
            display: flex;
            gap: 16px;
            flex-wrap: wrap;
        }}
        .finding-section {{
            font-size: 0.88rem;
            margin-top: 10px;
            color: #c9d1d9;
        }}
        .finding-section.remediation {{
            background: rgba(88,166,255,0.06);
            border: 1px solid rgba(88,166,255,0.2);
            border-radius: 6px;
            padding: 12px;
            margin-top: 12px;
        }}
        .poc-box, .evidence-box {{
            background: #090d13;
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 10px 12px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.82rem;
            color: #7ee787;
            overflow-x: auto;
            margin-top: 4px;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        .clean-state-box {{
            display: flex;
            align-items: center;
            gap: 16px;
            background: rgba(63,185,80,0.1);
            border: 1px solid rgba(63,185,80,0.3);
            border-radius: 8px;
            padding: 20px;
        }}
        .clean-icon {{ font-size: 1.8rem; }}
        code {{
            font-family: 'JetBrains Mono', monospace;
            background: rgba(255,255,255,0.08);
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.85em;
        }}
        ul {{ list-style-position: inside; margin-left: 8px; font-size: 0.9rem; color: #c9d1d9; }}
        li {{ margin-bottom: 6px; }}
        .footer-note {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--border);
            text-align: center;
            font-size: 0.8rem;
            color: var(--text-secondary);
        }}
        .print-btn-bar {{
            display: flex;
            justify-content: flex-end;
            margin-bottom: 16px;
        }}
        .print-btn {{
            background: var(--accent);
            color: #000;
            border: none;
            padding: 7px 14px;
            border-radius: 4px;
            font-weight: 700;
            cursor: pointer;
        }}
    </style>
</head>
<body>
    <div class="report-container">
        <div class="print-btn-bar">
            <button class="print-btn" onclick="window.print()">🖨️ Print / Save as PDF</button>
        </div>
        <header class="report-header">
            {logo_html}
            <h1 class="report-title">🛡️ Security Assessment & Bug Hunting Report</h1>
            <div class="report-meta-grid">
                <div><strong>Target Scope:</strong> <code>{html.escape(target)}</code></div>
                <div><strong>Scan ID:</strong> <code>{html.escape(scan_id)}</code></div>
                <div><strong>Date Generated:</strong> {date_str}</div>
                <div><strong>Assessor:</strong> {html.escape(profile.get('assessor') or operator or 'Not recorded')}</div>
                <div><strong>Classification:</strong> <span style="color: #f85149; font-weight: bold;">{html.escape(profile.get('classification') or 'CONFIDENTIAL')}</span></div>
            </div>
        </header>
        {identity_html}

        <section>
            <h2>1. Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <div class="summary-val">{total_assets}</div>
                    <div class="summary-label">Assets Discovered</div>
                </div>
                <div class="summary-card">
                    <div class="summary-val">{total_ports}</div>
                    <div class="summary-label">Open Ports</div>
                </div>
                <div class="summary-card">
                    <div class="summary-val">{total_urls}</div>
                    <div class="summary-label">Endpoints</div>
                </div>
                <div class="summary-card">
                    <div class="summary-val">{total_tech}</div>
                    <div class="summary-label">Technologies</div>
                </div>
                <div class="summary-card">
                    <div class="summary-val" style="color: {'var(--clean)' if not redacted_findings else 'var(--critical)'}">{len(redacted_findings)}</div>
                    <div class="summary-label">Findings</div>
                </div>
            </div>
        </section>

        <section>
            <h2>2. Scope & Authorization Boundary (§102)</h2>
            <p style="font-size: 0.9rem; color: #c9d1d9; margin-bottom: 8px;">
                Recorded Target: <code>{html.escape(target)}</code>. Execution scope, authorization, completed checks and safety outcomes must be reviewed in scan logs.
            </p>
        </section>

        <section>
            <h2>3. Attack Surface & Technology Inventory</h2>
            <ul>
                {tech_items}
            </ul>
        </section>

        <section>
            <h2>4. Recorded Security Findings & Proof of Concept (§52, §101)</h2>
            {findings_html}
        </section>

        <section>
            <h2>5. Methodology & Scope Verification</h2>
            <p style="font-size: 0.9rem; color: #8b949e;">
                Stored assessment records require human validation. Generated replay examples are not execution evidence. Sensitive fields are filtered, but review every export before sharing.
            </p>
        </section>

        <div class="footer-note">
            Generated by Hunter Aja Security Assessment Platform — Confidential Audit Record
        </div>
    </div>
</body>
</html>"""

    @classmethod
    def generate_pdf(cls, scan_id, target, stats, findings, assets, ports, technologies,
                     operator=None, view_perspective="customer", report_type="full") -> bytes:
        """Render canonical report content without blocking on external resources."""
        import re
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

        source = cls.generate_markdown(scan_id, target, stats, findings, assets, ports, technologies,
                                       operator, view_perspective)
        if report_type == "executive":
            source = source.split("## 3.", 1)[0] + "\n## Findings Requiring Review\n"
            for f in cls._prepare_findings(findings, view_perspective):
                source += (f"\n### [{f.get('severity')}] {f.get('title')}\n"
                           f"Readiness: {f['report_quality']['status']} | Missing: {', '.join(f['report_quality']['missing']) or 'None'}\n\n"
                           f"Impact: {f.get('business_impact') or f.get('impact') or 'Not recorded'}\n\n"
                           f"Remediation: {f.get('remediation') or 'Not recorded'}\n")
        elif report_type == "technical":
            source = "# Technical Evidence Report\n\n" + "\n".join(cls._engagement_lines(stats)) + "\n## 2." + source.split("## 2.", 1)[-1]
        source = source.replace("Security Assessment & Bug Hunting Report", f"{report_type.title()} Security Assessment Report")
        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4, rightMargin=40, leftMargin=40,
                                topMargin=44, bottomMargin=44, title=f"{report_type.title()} assessment - {target}")
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle("CodeLine", fontName="Courier", fontSize=7, leading=10,
                                  backColor=colors.HexColor("#f1f5f9"), splitLongWords=True))
        styles.add(ParagraphStyle("ReportBody", parent=styles["BodyText"], fontSize=9, leading=13,
                                  spaceAfter=4, splitLongWords=True))
        styles.add(ParagraphStyle("Cell", parent=styles["ReportBody"], fontSize=8, leading=11))
        for level, size in ((1, 18), (2, 13), (3, 11)):
            styles[f"Heading{level}"].fontSize = size
            styles[f"Heading{level}"].leading = size + 3
            styles[f"Heading{level}"].spaceBefore = 10 if level < 3 else 7
            styles[f"Heading{level}"].spaceAfter = 5
            styles[f"Heading{level}"].keepWithNext = True
        story = []
        logo = ((stats.get("report_context") or {}).get("report") or {}).get("logo_data_url") or ""
        if logo.startswith("data:image/png;base64,"):
            import base64
            from reportlab.platypus import Image as ReportImage
            logo_image = ReportImage(io.BytesIO(base64.b64decode(logo.split(",", 1)[1])), width=180, height=80, kind="proportional", hAlign="LEFT")
            story.extend([logo_image, Spacer(1, 12)])
        in_code = False
        table_rows = []

        def text(value):
            # Standard PDF fonts do not support emoji. Keep content legible on every host.
            return str(value).replace("—", "-").replace("–", "-").encode("cp1252", "ignore").decode("cp1252")

        def para(value, style="ReportBody"):
            escaped = html.escape(text(value))
            if style == "CodeLine":
                escaped = escaped.replace(" ", "&#160;")
            else:
                escaped = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", escaped)
                escaped = re.sub(r"`([^`]+)`", r"<font name='Courier'>\1</font>", escaped)
                escaped = re.sub(r"^_(.+)_$", r"<i>\1</i>", escaped)
            return Paragraph(escaped or " ", styles[style])

        def flush_table():
            if not table_rows:
                return
            columns = max(len(row) for row in table_rows)
            rows = [[para(cell, "Cell") for cell in row + [""] * (columns-len(row))] for row in table_rows]
            # Keep ordinary rows intact; only very tall evidence rows may split.
            oversized_row = any(max(cell.wrap(doc.width / columns - 12, doc.height)[1] for cell in row)
                                > doc.height - 60 for row in rows)
            table = Table(rows, colWidths=[doc.width / columns] * columns, repeatRows=1,
                          hAlign="LEFT", splitByRow=1, splitInRow=int(oversized_row))
            table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#e2e8f0")),
                                      ("VALIGN", (0,0), (-1,-1), "TOP"),
                                      ("GRID", (0,0), (-1,-1), .3, colors.HexColor("#cbd5e1")),
                                      ("LEFTPADDING", (0,0), (-1,-1), 6),
                                      ("RIGHTPADDING", (0,0), (-1,-1), 6)]))
            story.extend([table, Spacer(1,8)])
            table_rows.clear()

        for line in source.splitlines():
            if line.startswith("```"):
                flush_table()
                in_code = not in_code
                continue
            if in_code:
                # Short splittable paragraphs prevent long evidence from overflowing a page.
                for offset in range(0, max(1, len(line)), 105):
                    story.append(para(line[offset:offset+105], "CodeLine"))
                continue
            if line.startswith("|"):
                if not re.fullmatch(r"[| :\-]+", line):
                    table_rows.append([cell.strip() for cell in line.strip("|").split("|")])
                continue
            flush_table()
            if line.startswith("#"):
                level = min(3, len(line) - len(line.lstrip("#")))
                story.append(para(line.lstrip("# "), f"Heading{level}"))
            elif line.strip() and line.strip() != "---":
                story.append(para(line))
            elif story and not (isinstance(story[-1], Paragraph) and getattr(story[-1].style, "keepWithNext", False)):
                story.append(Spacer(1,2))
        flush_table()

        def footer(canvas, document):
            canvas.setFont("Helvetica", 8)
            canvas.setFillColor(colors.HexColor("#64748b"))
            classification = ((stats.get("report_context") or {}).get("report") or {}).get("classification") or "CONFIDENTIAL"
            canvas.drawString(40, 24, f"{text(classification)} | Evidence completeness requires human review")
            canvas.drawRightString(A4[0]-40, 24, f"Page {document.page}")

        doc.build(story, onFirstPage=footer, onLaterPages=footer)
        return buf.getvalue()

    @classmethod
    def generate_bug_bounty_markdown(cls, finding: Dict[str, Any], target: str) -> str:
        prepared = cls._prepare_findings([finding], "customer")[0]
        quality = prepared["report_quality"]
        dossier = prepared.get("poc_dossier") or {}
        evidence = prepared.get("evidence") or {}
        context = prepared.get("report_context") or {}
        rules = context.get("rules") or {}
        profile = context.get("report") or {}

        def text(value, fallback="Not recorded"):
            if isinstance(value, (dict, list)):
                return json.dumps(value, ensure_ascii=False, default=str)
            return str(value if value not in (None, "") else fallback).strip().replace("\r", " ")

        def code(value, language="text"):
            content = text(value)
            # Preserve evidence as data even if a response contains Markdown fences.
            fence = "`" * max(3, max((len(run) for run in re.findall(r"`+", content)), default=0) + 1)
            return f"{fence}{language}\n{content}\n{fence}"

        steps = prepared.get("reproduction_steps") or evidence.get("reproduction_steps") or []
        if not isinstance(steps, list):
            steps = [steps] if steps else []
        reproduction = [f"{index}. {text(step)}" for index, step in enumerate(steps, 1)]
        if not reproduction:
            reproduction = ["Reproduction steps were not captured. Do not treat the generated review checklist as a reproduced PoC."]
        structured = evidence.get("structured_validation") or {}
        captures = structured.get("evidence") or [] if isinstance(structured, dict) else []
        ids = structured.get("evidence_ids") or [] if isinstance(structured, dict) else []
        captures = [item for item in captures if isinstance(item, dict) and item.get("id") in ids]
        missing = list(quality.get("missing") or [])
        for name, value in {
            "authorization_and_scope": context.get("authorization_reference") and rules.get("authorization_acknowledged") and rules.get("scope_hosts"),
            "expected_secure_behavior": prepared.get("expected_result") or evidence.get("expected_result"),
            "preconditions": prepared.get("preconditions") or evidence.get("preconditions"),
        }.items():
            if not value:
                missing.append(name)
        status = "READY_FOR_HUMAN_REVIEW" if not missing and quality.get("confirmed_with_evidence") else "NEEDS_REVIEW"
        title = prepared.get("title") or "Security finding requires review"
        if "[REDACTED" in title:
            # A redacted title is not useful as a submission heading. Derive a
            # neutral label from stored classification without restoring secrets.
            title = f"{text(prepared.get('finding_type'), 'Security').replace('_', ' ').title()} finding on {RedactionEngine.redact_text(target)}"
        lines = [
            f"# {text(title)}", "",
            f"**Submission readiness:** `{status}`  ",
            f"**Evidence readiness:** `{quality.get('status', 'NEEDS_REVIEW')}`  ",
            f"**Finding ID:** `{text(prepared.get('finding_code') or prepared.get('id'))}`  ",
            f"**Platform / engagement:** {text(rules.get('platform'), 'Unspecified')} / {text(profile.get('program'))}  ",
            f"**Asset:** `{text(target)}`  ",
            f"**Endpoint:** `{text(prepared.get('location') or prepared.get('url') or evidence.get('url'))}`  ",
            f"**Method / parameter:** {text(dossier.get('method'))} / {text(dossier.get('parameter'))}  ",
            f"**Severity / weakness:** {text(prepared.get('severity'), 'UNRATED')} / {text(prepared.get('cwe_id'))}  ",
            f"**CVSS score / vector:** {text(prepared.get('cvss_score'))} / {text(prepared.get('cvss_vector'))} (recorded, not independently calculated)  ",
            f"**Evidence level / validation:** {text(prepared.get('evidence_level'), 'E0')} / {text(prepared.get('validation_status') or prepared.get('confidence'))}  ",
            f"**First / last observation:** {text(prepared.get('first_seen'))} / {text(prepared.get('last_seen'))}", "",
            "## Summary", "", text(prepared.get("executive_explanation") or prepared.get("description") or prepared.get("actual_result") or evidence.get("actual_result")), "",
            "## Authorization & Scope", "",
            f"- Authorization reference: {text(context.get('authorization_reference'))}",
            f"- In-scope hosts: {text(rules.get('scope_hosts'))}",
            f"- Excluded hosts: {text(rules.get('excluded_hosts'))}",
            f"- Allowed / prohibited techniques: {text(rules.get('allowed_techniques'))} / {text(rules.get('prohibited_techniques'))}",
            f"- Requested limit: {text(rules.get('max_rps'))} requests/second; verify tool-specific enforcement.",
            f"- Authorized window: {text(rules.get('starts_at'))} to {text(rules.get('ends_at'))}",
            "These are operator-supplied records, not independent proof of permission. Private research requires owner authorization even without a bounty program.", "",
            "## Description", "", text(prepared.get("description") or prepared.get("technical_details")), "",
            "## Preconditions & Test Identities", "", text(prepared.get("preconditions") or evidence.get("preconditions")), "",
            "## Steps To Reproduce", "", *reproduction, "",
            "## Expected vs Actual Result", "",
            "**Expected secure behavior:** " + text(prepared.get("expected_result") or evidence.get("expected_result")), "",
            "**Observed actual behavior:** " + text(prepared.get("actual_result") or evidence.get("actual_result")), "",
            "## Proof of Concept / Supporting Material", "",
            "**Replay provenance:** " + text((dossier.get("provenance") or {}).get("curl_command")),
            code(dossier.get("curl_command"), "bash"),
            "Replay examples require review and replacement of redacted values. They are not evidence that an exploit succeeded.", "",
            "### Recorded request", "", code(dossier.get("raw_http_request")), "",
            "### Recorded response", "", code(dossier.get("raw_http_response")), "",
            "### Evidence manifest", "", f"Referenced capture IDs: {text(ids)}. Captures below are sanitized recorded fields, not reconstructed raw HTTP.",
        ]
        for capture in captures[:20]:
            lines.extend(["", code(capture if len(text(capture)) <= 12000 else {
                "id": capture.get("id"), "preview": text(capture)[:12000],
                "note": "Preview shortened. Review the complete evidence package in the application."
            }, "json")])
        if len(captures) > 20:
            lines.append(f"Showing 20 of {len(captures)} captures; see the complete evidence package.")
        lines.extend([
            "", "## Impact", "", text(prepared.get("business_impact") or prepared.get("impact")),
            "Limit this claim to the security boundary and data access demonstrated above; hypothetical impact requires separate validation.", "",
            "## Root Cause", "", text(prepared.get("root_cause")), "",
            "## Remediation", "", text(prepared.get("remediation")), "",
            "## Coverage & Limitations", "",
            f"- Scan status: {text(context.get('scan_status'))}",
            f"- Coverage completion recorded: {text(context.get('coverage_complete'), 'Unknown')}",
            "- Known skipped/failed checks: " + text(context.get("coverage_failures"), "Not recorded"),
            "- A finding-level PoC does not establish full target coverage or absence of other vulnerabilities.", "",
            "## Researcher Review Checklist", "",
            f"- Missing evidence/context: {', '.join(missing) or 'None detected; human review remains required'}",
            "- Reproduce under the current scope and permitted techniques; verify baseline/control comparisons.",
            "- Check impact, affected versions, duplicate reports and program-specific exclusions.",
            "- Remove unnecessary secrets and personal data from every attachment before sharing.",
            "- Confirm disclosure/contact rules for HackerOne, other platforms, or the private asset owner.",
            "- AI wording is advisory. No automatic submission or acceptance is implied.",
        ])
        return RedactionEngine.redact_text("\n".join(lines))

    @classmethod
    def generate_cve_research_markdown(cls, finding: Dict[str, Any], target: str, researcher=None) -> str:
        intro = ("# Vulnerability Research Draft\n\n"
                 "CVE eligibility, affected product/version ranges, vendor acknowledgement and disclosure timeline require manual review. "
                 "No CVE assignment or validation is implied.\n\n")
        return intro + cls.generate_bug_bounty_markdown(finding, target)

    @classmethod
    def generate_reproduction_md(cls, finding: Dict[str, Any]) -> str:
        return cls.generate_bug_bounty_markdown(finding, finding.get("asset_hostname") or "Not recorded")
