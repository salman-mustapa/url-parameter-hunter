"""CVE-Ready Dossier Generator (V8 §38).

Generates standardized, audit-grade vulnerability submission dossiers for
unassigned or zero-day vulnerabilities conforming to MITRE CVE and CNA requirements.

Strict Rule:
Never fabricate or hallucinate a CVE ID. Uses 'CVE: Not Assigned / Candidate'.
"""

from __future__ import annotations

import datetime
import hashlib
from typing import Any, Dict, List, Optional

from app.validation.result import NormalizedValidationResult


class CveDossierGenerator:
    """Generates standard CVE submission dossiers (V8 §38)."""

    @classmethod
    def generate_dossier(
        cls,
        finding: Dict[str, Any],
        vendor_name: str = "Vendor Name",
        product_name: str = "Product Name",
        affected_versions: str = "<= Current Version",
        fixed_version: str = "Pending Vendor Patch",
        researcher_name: str = "Security Research Team",
    ) -> str:
        """Renders complete CVE-Ready Dossier Markdown."""
        date_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
        title = finding.get("title", "Security Vulnerability")
        vuln_type = finding.get("finding_type", "Vulnerability")
        cwe = finding.get("cwe_id") or "CWE-200"
        cvss = finding.get("cvss_score") or 7.5
        target = finding.get("target_host") or finding.get("url") or "Target Asset"
        endpoint = finding.get("endpoint_url") or finding.get("url") or "/"
        root_cause = finding.get("root_cause") or "Improper input sanitization or missing authorization boundary in parameter processing."
        desc = finding.get("description") or f"A validated {vuln_type} vulnerability was confirmed in {product_name}."
        repro = finding.get("reproduction_steps") or finding.get("reproduction_md") or "1. Send crafted request to endpoint.\n2. Observe response indicating exploit condition."
        if isinstance(repro, list):
            repro_md = "\n".join(f"{i+1}. {step}" for i, step in enumerate(repro))
        else:
            repro_md = str(repro)

        poc = finding.get("poc") or finding.get("poc_curl") or finding.get("poc_command") or f"curl -s -k '{endpoint}'"

        dossier_md = f"""# CVE Vulnerability Submission Dossier

**Vulnerability Title:** {title}  
**CVE Identifier:** `CVE: Not Assigned / Candidate`  
**Date of Discovery:** `{date_str}`  
**Researcher Attribution:** `{researcher_name}`  
**Classification:** `COORDINATED VULNERABILITY DISCLOSURE (TLP:CLEAR)`  

---

## 1. Product & Component Identification
- **Vendor:** `{vendor_name}`
- **Product:** `{product_name}`
- **Component / Endpoint:** `{endpoint}`
- **Vulnerability Class:** `{vuln_type}` ({cwe})
- **Affected Versions:** `{affected_versions}`
- **Fixed Version:** `{fixed_version}`

---

## 2. Vulnerability Assessment
- **Common Weakness Enumeration:** `{cwe}`
- **Base CVSS v4.0 Score:** `{cvss}`
- **Attack Vector:** Network (`AV:N`)
- **Attack Complexity:** Low (`AC:L`)
- **Privileges Required:** None (`PR:N`)
- **User Interaction:** None (`UI:N`)

---

## 3. Technical Description & Root Cause
{desc}

### Root Cause Analysis
{root_cause}

### Prerequisites & Attack Scenario
- Network access to `{target}`
- Target service active and processing incoming requests

---

## 4. Minimal Reproduction Steps (PoC)
{repro_md}

### Proof of Concept Command
```bash
{poc}
```

---

## 5. Security Impact
{finding.get('business_impact') or 'Exploitation allows remote attackers to compromise data confidentiality and integrity without prior authentication.'}

---

## 6. Coordinated Disclosure Timeline
- **{date_str}:** Vulnerability identified and reproduced via automated controlled validation.
- **{date_str}:** Initial vendor contact initiated and technical dossier compiled.
- **Pending:** Vendor patch verification and public CVE identifier assignment.

---

## 7. Recommended Remediation
{finding.get('remediation') or 'Apply input sanitization, enforce strict authorization checks, and update to the latest vendor release.'}

---

## 8. References
- [{cwe} Reference](https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '') if 'CWE-' in cwe else '200'}.html)
- OWASP Top 10 Guidelines
"""
        return dossier_md
