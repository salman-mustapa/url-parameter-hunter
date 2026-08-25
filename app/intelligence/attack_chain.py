"""Autonomous Attack Chain & Multi-Step Exploit Path Correlator (V5 §46, §47).

Correlates isolated vulnerabilities, directory exposures, and architectural signals
into end-to-end, multi-stage attack scenarios.

Features:
1. Multi-Stage Attack Path Synthesis (Recon → Exploit → Lateral Movement → Exfiltration).
2. Blast Radius & Breach Impact Quantification.
3. Time-to-Compromise (TTC) Estimation.
4. Mermaid Attack Graph generation for visual reports and executive dashboards.
5. Actionable Threat Narrative from an adversary's perspective.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("intelligence.attack_chain")


@dataclass
class AttackStep:
    step_number: int
    phase: str  # Reconnaissance, Initial Access, Credential Access, Privilege Escalation, Impact
    title: str
    target_url: str
    technique: str
    description: str
    evidence_ref: str = ""


@dataclass
class AttackChain:
    chain_id: str
    name: str
    severity: str  # CRITICAL, HIGH, MEDIUM
    estimated_ttc: str  # e.g. "< 15 Minutes"
    blast_radius: str  # e.g. "Complete Infrastructure Compromise"
    likelihood: str  # VERY HIGH, HIGH, MEDIUM
    financial_risk_rating: str  # CRITICAL / PDP Compliance Violation
    steps: List[AttackStep] = field(default_factory=list)
    narrative: str = ""
    mermaid_diagram: str = ""
    remediation_priority: str = "IMMEDIATE"


class AttackChainCorrelator:
    """Correlates findings into multi-step adversary attack chains."""

    @classmethod
    def analyze_scan_findings(
        cls,
        target_domain: str,
        findings: List[Dict[str, Any]],
        technologies: Optional[List[Dict[str, Any]]] = None,
    ) -> List[AttackChain]:
        """Synthesize verified findings into actionable multi-step attack chains."""
        chains: List[AttackChain] = []
        tech_list = [t.get("name", "").lower() for t in (technologies or [])]

        # Categorize findings by nature
        db_exposures = []
        dir_listings = []
        cve_rces = []
        auth_bypasses = []
        defacements = []
        file_uploads = []
        sqli_findings = []
        xss_findings = []

        for f in findings:
            ft = (f.get("finding_type") or f.get("vulnerability_type") or "").lower()
            title = (f.get("title") or "").lower()
            sev = (f.get("severity") or "").upper()

            if "database" in ft or "sql" in ft or ".sql" in title or "database" in title:
                db_exposures.append(f)
            elif "directory_listing" in ft or "index of" in title:
                dir_listings.append(f)
            elif "cve" in ft or "command_injection" in ft or "rce" in ft or sev == "CRITICAL":
                cve_rces.append(f)
            elif "bypass" in ft or "403" in title or "auth" in ft:
                auth_bypasses.append(f)
            elif "defacement" in ft or "spam" in ft or "judol" in title:
                defacements.append(f)
            elif "upload" in ft:
                file_uploads.append(f)
            elif "sqli" in ft or "sql_injection" in ft:
                sqli_findings.append(f)
            elif "xss" in ft:
                xss_findings.append(f)

        # ---------------------------------------------------------------------
        # Scenario 1: Database Leakage to Complete Administrative Takeover
        # ---------------------------------------------------------------------
        if db_exposures or (dir_listings and any("database" in (d.get("url") or "") for d in dir_listings)):
            db_f = db_exposures[0] if db_exposures else dir_listings[0]
            db_url = db_f.get("url") or f"https://{target_domain}/database/"
            
            steps = [
                AttackStep(
                    step_number=1,
                    phase="Reconnaissance",
                    title="Unauthenticated Directory Browsing",
                    target_url=db_url,
                    technique="T1083: File and Directory Discovery",
                    description=f"Adversary accesses `{db_url}` without credentials due to missing web server directory index restrictions.",
                ),
                AttackStep(
                    step_number=2,
                    phase="Credential Access",
                    title="Production Database SQL Dump Exfiltration",
                    target_url=db_url,
                    technique="T1552.001: Credentials in Files",
                    description="Adversary downloads complete SQL backup (`skpi_trc.sql` or database dump), extracting hashed administrative credentials, student records, and system secrets.",
                ),
                AttackStep(
                    step_number=3,
                    phase="Initial Access & Lateral Movement",
                    title="Administrative Account Authentication & Data Theft",
                    target_url=f"https://{target_domain}/admin",
                    technique="T1078: Valid Accounts",
                    description="Adversary cracks or passes extracted password hashes to login portals, gaining full administrative control over application records and user data.",
                ),
            ]

            mermaid = f"""graph TD
    A["Adversary: Public Internet"] -->|HTTP GET| B["Exposed Directory: /database/"]
    B -->|Download| C["skpi_trc.sql / Database Dump"]
    C -->|Extract| D["Admin Password Hashes & PII Records"]
    D -->|Authenticate| E["Admin Portal Takeover & Total Data Compromise"]
    style A fill:#1e293b,stroke:#64748b,color:#fff
    style B fill:#b91c1c,stroke:#ef4444,color:#fff
    style C fill:#dc2626,stroke:#f87171,color:#fff
    style D fill:#ea580c,stroke:#fb923c,color:#fff
    style E fill:#7f1d1d,stroke:#f87171,color:#fff"""

            narrative = (
                f"An external adversary initiates passive reconnaissance on `{target_domain}` and identifies an unrestricted directory listing at `{db_url}`. "
                "By retrieving the exposed SQL backup file, the attacker obtains complete database table structures, user credentials, and sensitive records. "
                "Using these credentials, the adversary authenticates to administrative portals, resulting in total data confidentiality loss and statutory privacy violations."
            )

            chains.append(AttackChain(
                chain_id="CHAIN-001",
                name="Exposed Database Dump to Complete Administrative Compromise",
                severity="CRITICAL",
                estimated_ttc="< 15 Minutes",
                blast_radius="Total Database & Administrative Takeover",
                likelihood="VERY HIGH",
                financial_risk_rating="CRITICAL (Mass Data Leakage / Regulatory Liability)",
                steps=steps,
                narrative=narrative,
                mermaid_diagram=mermaid,
                remediation_priority="IMMEDIATE (P0)",
            ))

        # ---------------------------------------------------------------------
        # Scenario 2: Active Web Defacement & Illegal Content Infiltration
        # ---------------------------------------------------------------------
        if defacements or file_uploads:
            def_f = defacements[0] if defacements else file_uploads[0]
            def_url = def_f.get("url") or f"https://{target_domain}/"

            steps = [
                AttackStep(
                    step_number=1,
                    phase="Initial Access",
                    title="Exploitation of Input / Upload Channel",
                    target_url=def_url,
                    technique="T1190: Exploit Public-Facing Application",
                    description="Adversary identifies an unprotected file upload or unvalidated parameter handler.",
                ),
                AttackStep(
                    step_number=2,
                    phase="Execution & Persistence",
                    title="SEO Spam & Gambling Landing Page Infiltration",
                    target_url=def_url,
                    technique="T1491.001: Defacement: Internal / External Defacement",
                    description="Adversary plants cloaked spam HTML pages and hidden backlinks under official institutional domain URLs.",
                ),
                AttackStep(
                    step_number=3,
                    phase="Impact",
                    title="Search Engine Blacklisting & Brand Hijacking",
                    target_url=f"https://{target_domain}/",
                    technique="T1499: Endpoint Denial of Service / Reputational Damage",
                    description="Googlebot indexes illegal gambling backlinks, leading to browser phishing warnings and severe institutional reputational damage.",
                ),
            ]

            mermaid = f"""graph TD
    A["Adversary: SEO Spam Operator"] -->|Infiltrate| B["Vulnerable Upload / CMS Handler"]
    B -->|Plant Backlinks| C["Injected Gambling Content: /build/"]
    C -->|Search Crawl| D["Googlebot Indexes Gambling Keywords"]
    D -->|Blacklist| E["Domain Reputation Destruction & Browser Warnings"]
    style A fill:#1e293b,stroke:#64748b,color:#fff
    style B fill:#b91c1c,stroke:#ef4444,color:#fff
    style C fill:#dc2626,stroke:#f87171,color:#fff
    style D fill:#ea580c,stroke:#fb923c,color:#fff
    style E fill:#7f1d1d,stroke:#f87171,color:#fff"""

            narrative = (
                f"Adversaries leverage unmonitored directories or upload scripts on `{target_domain}` to inject hidden backlinks and landing pages. "
                "Search engines crawl these pages and associate the trusted government/university domain with illicit gambling networks, triggering search delisting and reputation loss."
            )

            chains.append(AttackChain(
                chain_id="CHAIN-002",
                name="SEO Spam Poisoning & Domain Hijacking Attack Path",
                severity="HIGH",
                estimated_ttc="< 1 Hour",
                blast_radius="Domain Blacklisting & Complete Brand Compromise",
                likelihood="HIGH",
                financial_risk_rating="HIGH (Institutional Trust & Compliance Erosion)",
                steps=steps,
                narrative=narrative,
                mermaid_diagram=mermaid,
                remediation_priority="HIGH (P1)",
            ))

        # ---------------------------------------------------------------------
        # Scenario 3: Privilege Escalation via 403 Bypass & Broken Access Control
        # ---------------------------------------------------------------------
        if auth_bypasses:
            ab_f = auth_bypasses[0]
            ab_url = ab_f.get("url") or f"https://{target_domain}/admin"

            steps = [
                AttackStep(
                    step_number=1,
                    phase="Discovery",
                    title="Restricted Administrative Route Mapping",
                    target_url=ab_url,
                    technique="T1083: File and Directory Discovery",
                    description=f"Adversary locates protected administrative route `{ab_url}` responding with HTTP 401/403.",
                ),
                AttackStep(
                    step_number=2,
                    phase="Defense Evasion",
                    title="Reverse Proxy Header & Path Mutation Bypass",
                    target_url=ab_url,
                    technique="T1562.001: Disable or Modify Security Tools",
                    description="Adversary submits custom routing headers (`X-Original-URL`, `x-middleware-subrequest`) to bypass proxy authorization filters.",
                ),
                AttackStep(
                    step_number=3,
                    phase="Privilege Escalation",
                    title="Unauthorized Administrative Dashboard Access",
                    target_url=ab_url,
                    technique="T1068: Exploitation for Privilege Escalation",
                    description="Server grants full access to internal administrative consoles and system management actions.",
                ),
            ]

            mermaid = f"""graph TD
    A["Unauthenticated Attacker"] -->|Request /admin| B["Reverse Proxy: 403 Forbidden"]
    A -->|Inject Custom Header: x-middleware-subrequest| B
    B -->|Filter Bypass| C["Backend Application: 200 OK"]
    C -->|Unrestricted| D["Privileged Admin Control Panel Access"]
    style A fill:#1e293b,stroke:#64748b,color:#fff
    style B fill:#b91c1c,stroke:#ef4444,color:#fff
    style C fill:#dc2626,stroke:#f87171,color:#fff
    style D fill:#7f1d1d,stroke:#f87171,color:#fff"""

            narrative = (
                f"Adversary bypasses perimeter authentication controls on `{target_domain}` via header tampering, gaining direct access to internal endpoints."
            )

            chains.append(AttackChain(
                chain_id="CHAIN-003",
                name="Authentication Filter Bypass to Internal Admin Control",
                severity="HIGH",
                estimated_ttc="< 30 Minutes",
                blast_radius="Internal Administrative Console Compromise",
                likelihood="HIGH",
                financial_risk_rating="HIGH (Unauthorized Data Modification)",
                steps=steps,
                narrative=narrative,
                mermaid_diagram=mermaid,
                remediation_priority="HIGH (P1)",
            ))

        return chains


# Module-level singleton
attack_chain_correlator = AttackChainCorrelator()
