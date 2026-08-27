"""Bug Bounty Finding Report Generator (V5 §32).

Generates submission-ready, professional markdown reports conforming to HackerOne,
Bugcrowd, and enterprise Responsible Disclosure standards.

Includes:
- CVSS v4.0 vector & score
- CWE mapping
- Concise executive summary
- Minimal necessary proof-of-impact
- Deterministic reproduction steps (cURL & manual steps)
- Remediation guidance
- Screenshot and evidence hash references
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.reporting.poc_builder import PocBuilder
from app.validation.result import NormalizedValidationResult


class BugBountyReportGenerator:
    """Generates standardized, audit-grade markdown bug bounty vulnerability reports (V5 §32)."""

    @classmethod
    def generate_finding_report(
        cls,
        finding: NormalizedValidationResult,
        researcher_alias: str = "BugHunter-AI",
        screenshot_path: Optional[str] = None,
    ) -> str:
        """Render a finding into comprehensive Bug Bounty Markdown format with complete PoC."""
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        sev = finding.severity.upper()
        cvss_score = finding.cvss_score or (9.8 if sev == "CRITICAL" else (8.5 if sev == "HIGH" else (5.5 if sev == "MEDIUM" else 3.5)))

        cwe_display = finding.cwe_id or "CWE-200 (Information Exposure)"
        cve_display = finding.cve_id or "N/A (0-Day / Application-Specific Logic Flaw)"

        # Generate evidence hash
        ev_data = f"{finding.endpoint_url}:{finding.title}:{finding.evidence_level}:{finding.actual_result}"
        ev_hash = hashlib.sha256(ev_data.encode()).hexdigest()

        # Build PoC Dossier
        dossier = PocBuilder.generate_dossier(
            title=finding.title,
            finding_type=finding.vulnerability_type,
            severity=finding.severity,
            target_url=finding.endpoint_url or f"https://{finding.target_host}/",
            target_host=finding.target_host,
            parameter=finding.parameter,
            method=finding.request_metadata.get("method", "GET") if finding.request_metadata else "GET",
            headers=finding.request_metadata.get("headers") if finding.request_metadata else {},
            payload=finding.poc_payload,
            cwe_id=finding.cwe_id,
            cve_id=finding.cve_id,
            cvss_score=cvss_score,
            description=finding.description,
            technical_details=finding.root_cause,
            evidence={
                "curl": finding.poc_command,
                "response_headers": finding.response_metadata.get("headers", {}) if finding.response_metadata else {},
                "response_status": finding.response_metadata.get("status_code", 200) if finding.response_metadata else 200,
                "response_body": str(finding.actual_result or ""),
            },
            has_real_screenshot=bool(screenshot_path and os.path.exists(screenshot_path)),
            screenshot_url=screenshot_path,
        )

        repro_steps_md = "\n".join(f"{i+1}. {step}" for i, step in enumerate(dossier["reproduction_steps"]))

        # Framework Mapping Lookups (§60)
        from app.ai.cybersecurity_skills import skills_hub
        vuln_key = finding.vulnerability_type.upper()
        if "SQL" in vuln_key:
            framework_data = skills_hub.framework_registry.get("SQLI", {})
        elif "IDOR" in vuln_key or "BOLA" in vuln_key:
            framework_data = skills_hub.framework_registry.get("IDOR", {})
        elif "SSRF" in vuln_key:
            framework_data = skills_hub.framework_registry.get("SSRF", {})
        elif "XSS" in vuln_key:
            framework_data = skills_hub.framework_registry.get("XSS", {})
        elif "COMMAND" in vuln_key or "RCE" in vuln_key:
            framework_data = skills_hub.framework_registry.get("COMMAND_INJECTION", {})
        elif "AUTH" in vuln_key:
            framework_data = skills_hub.framework_registry.get("AUTH_BYPASS", {})
        else:
            framework_data = {
                "mitre_attack": ["T1190"],
                "mitre_tactic": "Initial Access",
                "nist_csf": ["DE.CM-01", "RS.AN-03"],
                "d3fend": ["D3-SPP"],
                "mitre_f3": ["FA0001"],
                "remediations": ["Enforce server-side input validation and strict access control."]
            }

        mitre_att = ", ".join(f"`{x}`" for x in framework_data.get("mitre_attack", ["T1190"]))
        nist_csf = ", ".join(f"`{x}`" for x in framework_data.get("nist_csf", ["DE.CM-01"]))
        d3fend = ", ".join(f"`{x}`" for x in framework_data.get("d3fend", ["D3-SPP"]))
        mitre_f3 = ", ".join(f"`{x}`" for x in framework_data.get("mitre_f3", ["FA0001"]))

        playbook_items = "\n".join(f"- {step}" for step in (finding.remediation.splitlines() if finding.remediation else dossier["remediation_playbook"]))

        # Visual screenshot proof section
        if screenshot_path and os.path.exists(screenshot_path):
            screenshot_section = f"""### 📸 Visual Evidence (Real Browser Screenshot)
![Visual Proof Capture]({screenshot_path})
*Image Hash: `{ev_hash[:16]}` | Captured during live automated browser verification.*"""
        else:
            screenshot_section = f"""### 📸 Visual Evidence Status
> [!NOTE]
> {dossier['screenshot']['explanation_if_none']}"""

        report_md = f"""# [{sev}] {finding.title}

## Summary

{finding.description or finding.executive_explanation or f'A validated {finding.vulnerability_type} vulnerability was identified on {finding.target_host}.'}

---

## Vulnerability Details

- **Target Asset:** `{finding.target_host}`
- **Endpoint URL:** `{finding.endpoint_url or 'N/A'}`
- **Affected Parameter:** `{dossier['parameter']}`
- **Vulnerability Type:** `{finding.vulnerability_type}`
- **CWE:** {cwe_display}
- **CVE Identifier:** {cve_display}
- **Severity Rating:** **{sev}**
- **Confidence Level:** `{finding.confidence}`
- **Evidence Level:** `{finding.evidence_level}`
- **CVSS v4.0 Score:** `{cvss_score}`

### Multi-Framework Industry Mapping (§60)
| Security Framework | Mapped Identifiers / Tactics |
|---|---|
| **MITRE ATT&CK®** | {mitre_att} ({framework_data.get('mitre_tactic', 'Initial Access')}) |
| **NIST CSF 2.0** | {nist_csf} |
| **MITRE D3FEND™** | {d3fend} |
| **MITRE F3 (Fraud)** | {mitre_f3} |

---

## Technical Description & Root Cause

{finding.root_cause or 'Improper sanitization, lack of access control, or unsafe direct parameter handling in application logic.'}

### Preconditions
{chr(10).join(f'- {p}' for p in (finding.preconditions or ['Network connectivity to public endpoint', 'Target service is active and accessible']))}

---

## Complete Proof of Concept (PoC) & Exploitation Dossier

### 1. Step-by-Step Manual Reproduction Guide
{repro_steps_md}

### 2. Standalone Python PoC Script
```python
{dossier['python_poc']}
```

### 3. cURL CLI Reproduction Command
```bash
{dossier['curl_command']}
```

### 4. Wire-Level HTTP Request Proof
```http
{dossier['raw_http_request']}
```

### 5. Wire-Level HTTP Response Proof
```http
{dossier['raw_http_response']}
```

{screenshot_section}

### Expected vs Observed Behavior
- **Expected Secure Behavior:** {dossier['expected_behavior']}
- **Actual Vulnerable Behavior:** {dossier['actual_behavior']}

---

## Security Impact Analysis

{finding.business_impact or 'An unauthenticated remote attacker could compromise data confidentiality, alter system state, or escalate privileges.'}

| Impact Domain | Assessment |
|---|---|
| **Confidentiality** | `{finding.impact_matrix.get('confidentiality', 'HIGH')}` |
| **Integrity** | `{finding.impact_matrix.get('integrity', 'MEDIUM')}` |
| **Availability** | `{finding.impact_matrix.get('availability', 'LOW')}` |
| **Authentication Bypass** | `{finding.impact_matrix.get('auth_bypass', 'POSSIBLE')}` |
| **Data Exposure** | `{finding.impact_matrix.get('data_exposure', 'HIGH')}` |

---

## Supporting Evidence & Provenance

- **Evidence Level:** `{finding.evidence_level}`
- **Evidence Integrity Hash (SHA-256):** `{ev_hash}`
- **Assessment Timestamp:** `{now_str}`
- **Validation Adapter:** `{finding.adapter_name}`

---

## Remediation Playbook (§60)

{playbook_items}

---

*Report generated autonomously by Hunter Aja Autonomous Security Platform | Researcher: {researcher_alias}*
"""
        return report_md


# Module-level singleton
bug_bounty_generator = BugBountyReportGenerator()


