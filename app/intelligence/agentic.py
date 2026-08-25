"""Agentic AI Testing Decision Engine (V4 & V5).

Autonomous pentesting decision engine that dynamically evaluates scan telemetry
(assets, open ports, technologies, endpoints, response status codes, parameter shapes)
and orchestrates iterative next-step security test strategies.

Features:
1. Context-Aware Strategy Formulation: Recommends specific attack chains based on technology footprint.
2. 403/Blocked Endpoint Attack Chaining: Auto-schedules bypass when privileged endpoints return 401/403.
3. Tech Stack CVE Prioritization: Triggers precision exploit validations based on fingerprint matches.
4. Parameter Anomaly Escalation: Prioritizes deep injection probes when input reflection or error signals emerge.
5. Adaptive Reasoning: Evaluates intermediate results to suggest payload variants and validation escalations.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("intelligence.agentic")


@dataclass
class TestDecision:
    """Actionable test decision emitted by the Agentic Decision Engine."""
    module_id: str
    target_url: str
    target_host: str
    priority: int  # 0 (P0 Critical/Immediate), 1 (High), 2 (Medium), 3 (Low)
    rationale: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


class AgenticDecisionEngine:
    """Agentic security test planner and reasoning engine."""

    def __init__(self) -> None:
        self.reasoning_log: List[str] = []

    def log_thought(self, message: str) -> None:
        logger.info("[Agentic AI] %s", message)
        self.reasoning_log.append(message)

    async def evaluate_and_plan(
        self,
        target_domain: str,
        assets: List[Dict[str, Any]],
        technologies: List[Dict[str, Any]],
        urls: List[Dict[str, Any]],
        ports: List[Dict[str, Any]],
        existing_findings: List[Dict[str, Any]],
    ) -> List[TestDecision]:
        """Analyze current assessment state and formulate prioritized next test actions."""
        decisions: List[TestDecision] = []
        self.log_thought(f"Initiating autonomous assessment reasoning for {target_domain}")

        tech_names = [t.get("name", "").lower() for t in technologies]
        tech_map = {t.get("name", "").lower(): t.get("version", "") for t in technologies}

        # 1. Evaluate Technologies for Immediate CVE/Exploit Validation (P0)
        for tech in technologies:
            name = (tech.get("name") or "").lower()
            ver = tech.get("version") or ""
            host = tech.get("hostname") or target_domain
            base_url = f"https://{host}"

            if "apache" in name:
                self.log_thought(f"Identified Apache ({ver}) on {host}. Scheduling CVE & Path Traversal probe.")
                decisions.append(TestDecision(
                    module_id="cve_exploiter",
                    target_url=base_url,
                    target_host=host,
                    priority=0,
                    rationale=f"Apache HTTP Server ({ver or 'unknown'}) detected; execute CVE-2021-41773/42013 and info disclosure probes.",
                    parameters={"tech": "apache", "version": ver},
                ))

            if "nginx" in name:
                self.log_thought(f"Identified Nginx ({ver}) on {host}. Scheduling Alias Traversal & default page audit.")
                decisions.append(TestDecision(
                    module_id="cve_exploiter",
                    target_url=base_url,
                    target_host=host,
                    priority=1,
                    rationale=f"Nginx ({ver or 'unknown'}) detected; test alias traversal misconfigurations and default pages.",
                    parameters={"tech": "nginx", "version": ver},
                ))

            if "php" in name:
                self.log_thought(f"PHP runtime detected on {host}. Scheduling phpinfo & CGI argument injection checks.")
                decisions.append(TestDecision(
                    module_id="cve_exploiter",
                    target_url=base_url,
                    target_host=host,
                    priority=0,
                    rationale="PHP environment detected; testing for exposed phpinfo(), .env, and CVE-2024-4577.",
                    parameters={"tech": "php", "version": ver},
                ))

            if "next.js" in name or "nextjs" in name or "__next_data__" in name:
                self.log_thought(f"Next.js framework identified on {host}. Scheduling SSRF and middleware bypass testing.")
                decisions.append(TestDecision(
                    module_id="cve_exploiter",
                    target_url=base_url,
                    target_host=host,
                    priority=0,
                    rationale="Next.js detected; testing for CVE-2024-34351 SSRF and CVE-2025-29927 middleware bypass.",
                    parameters={"tech": "next.js", "version": ver},
                ))

            if "spring" in name:
                self.log_thought(f"Spring Boot detected on {host}. Scheduling Actuator dump and Spring4Shell verification.")
                decisions.append(TestDecision(
                    module_id="cve_exploiter",
                    target_url=base_url,
                    target_host=host,
                    priority=0,
                    rationale="Spring Boot detected; testing Actuator sensitive endpoints and Spring4Shell (CVE-2022-22965).",
                    parameters={"tech": "spring", "version": ver},
                ))

            if "laravel" in name:
                self.log_thought(f"Laravel detected on {host}. Scheduling debug ignition & .env verification.")
                decisions.append(TestDecision(
                    module_id="cve_exploiter",
                    target_url=base_url,
                    target_host=host,
                    priority=0,
                    rationale="Laravel framework detected; checking for exposed debug pages and .env files.",
                    parameters={"tech": "laravel", "version": ver},
                ))

            if "wordpress" in name:
                self.log_thought(f"WordPress detected on {host}. Scheduling deep WordPress assessment suite.")
                decisions.append(TestDecision(
                    module_id="wordpress_deep",
                    target_url=base_url,
                    target_host=host,
                    priority=0,
                    rationale=f"WordPress {ver or ''} detected; executing user enumeration, XML-RPC audit, plugin CVEs, and config leaks.",
                    parameters={"tech": "wordpress", "version": ver},
                ))

        # 2. Evaluate Blocked / 403 / 401 Endpoints for Access Control Bypass (P0 / P1)
        for u in urls:
            status = u.get("status_code", 0)
            url_str = u.get("url", "")
            host = u.get("host") or target_domain

            if status in (401, 403):
                self.log_thought(f"Endpoint {url_str} returned HTTP {status}. Queuing 403 Access Control Bypass Engine.")
                decisions.append(TestDecision(
                    module_id="bypass_403",
                    target_url=url_str,
                    target_host=host,
                    priority=0,
                    rationale=f"HTTP {status} returned on {url_str}; attempting header injection, path mutations, and method switching.",
                    parameters={"original_status": status},
                ))

        # 3. Evaluate Authentication Portals for Controlled Brute-Force & Policy Verification (P1)
        auth_patterns = ["login", "signin", "auth", "wp-login", "admin/login", "user/login", "portal"]
        for u in urls:
            url_str = u.get("url", "")
            host = u.get("host") or target_domain
            if any(pat in url_str.lower() for pat in auth_patterns):
                self.log_thought(f"Authentication entrypoint detected at {url_str}. Queuing safe credential audit.")
                decisions.append(TestDecision(
                    module_id="controlled_brute_force",
                    target_url=url_str,
                    target_host=host,
                    priority=1,
                    rationale=f"Login portal identified at {url_str}; performing rate-limited, bounded credential & lockout policy verification.",
                    parameters={"url": url_str},
                ))
                break  # Test top candidate per host

        # 4. Evaluate Open Network Services (SSH / RDP / Database) (P1)
        for p in ports:
            port_num = p.get("port")
            ip = p.get("ip") or target_domain
            host = p.get("hostname") or target_domain
            if port_num == 22 and p.get("state") == "open":
                self.log_thought(f"Port 22 SSH open on {ip}. Scheduling SSH cryptographic & protocol audit.")
                decisions.append(TestDecision(
                    module_id="ssh_assessment",
                    target_url=f"ssh://{ip}:22",
                    target_host=host,
                    priority=1,
                    rationale=f"SSH Port 22 open on {ip}; inspecting KEX algorithms, ciphers, and regreSSHion/Terrapin vulnerabilities.",
                    parameters={"ip": ip, "port": 22},
                ))
            elif port_num == 3389 and p.get("state") == "open":
                self.log_thought(f"Port 3389 RDP open on {ip}. Scheduling NLA & protocol negotiation audit.")
                decisions.append(TestDecision(
                    module_id="rdp_assessment",
                    target_url=f"rdp://{ip}:3389",
                    target_host=host,
                    priority=1,
                    rationale=f"RDP Port 3389 open on {ip}; assessing Network Level Authentication (NLA) status and BlueKeep exposure.",
                    parameters={"ip": ip, "port": 3389},
                ))

        # 5. Evaluate Parameter Discovery for Deep Injection Chains (P1 / P2)
        params_found = [u for u in urls if "?" in u.get("url", "")]
        if params_found:
            self.log_thought(f"Discovered {len(params_found)} URLs with parameters. Recommending deep fuzzing & canary probes.")
            for pf in params_found[:15]:
                decisions.append(TestDecision(
                    module_id="parameter_injection_suite",
                    target_url=pf.get("url", ""),
                    target_host=pf.get("host") or target_domain,
                    priority=2,
                    rationale="Dynamic parameters detected; performing coordinated SQLi, XSS, SSRF, RCE, and IDOR differential testing.",
                    parameters={"url": pf.get("url")},
                ))

        # Sort by priority
        decisions.sort(key=lambda d: d.priority)
        self.log_thought(f"Formulated {len(decisions)} autonomous test execution decisions.")
        return decisions

    async def adapt_on_finding(
        self,
        finding: Dict[str, Any],
        target_domain: str,
    ) -> List[TestDecision]:
        """Perform real-time adaptive reasoning upon discovering a new finding."""
        escalations: List[TestDecision] = []
        ftype = finding.get("vulnerability_type", "")
        url = finding.get("endpoint_url", "")
        param = finding.get("parameter", "")
        host = finding.get("target_host", target_domain)

        # Escalation 1: Boolean SQLi detected -> trigger UNION & database fingerprinting escalation
        if ftype == "sql_injection":
            self.log_thought(f"SQL Injection signal confirmed on parameter '{param}'. Escalating to UNION extraction & DB fingerprinting.")
            escalations.append(TestDecision(
                module_id="sqli_union_escalation",
                target_url=url,
                target_host=host,
                priority=0,
                rationale=f"SQLi detected on '{param}'; execute UNION-based column enumeration and version extraction for E3 proof.",
                parameters={"url": url, "parameter": param},
            ))

        # Escalation 2: Reflected XSS observed -> escalate to DOM execution & context bypass
        if ftype == "xss_reflection":
            self.log_thought(f"Reflected input found on parameter '{param}'. Escalating to script execution confirmation.")
            escalations.append(TestDecision(
                module_id="xss_execution_proof",
                target_url=url,
                target_host=host,
                priority=0,
                rationale=f"Reflection detected on '{param}'; validating active DOM script execution and browser screenshot proof.",
                parameters={"url": url, "parameter": param},
            ))

        # Escalation 3: 403 bypass confirmed on an admin URL -> immediate IDOR and Auth Bypass sweep on sub-paths
        if ftype == "authentication_bypass" or "403" in finding.get("title", ""):
            self.log_thought(f"Privilege boundary broken at {url}. Scheduling full subtree crawl and API authorization analysis.")
            escalations.append(TestDecision(
                module_id="auth_subtree_crawl",
                target_url=url,
                target_host=host,
                priority=0,
                rationale=f"Bypass successful at {url}; spidering internal routes for secondary IDOR and object-level authorization flaws.",
                parameters={"base_url": url},
            ))

        # Escalation 4: SQL dump exposure -> harvest credentials and test against login forms
        if ftype in ("db_exposure", "backup_sql", "sql_dump"):
            self.log_thought(f"SQL dump artifact discovered at {url}. Escalating to credential harvest and auth retest pipeline.")
            escalations.append(TestDecision(
                module_id="credential_harvest_from_dump",
                target_url=url,
                target_host=host,
                priority=0,
                rationale=f"SQL dump at {url} may contain admin credentials; extracting users/hashes and testing against discovered login forms.",
                parameters={"artifact_url": url, "escalation_type": "sql_dump_credential_reuse"},
            ))

        # Escalation 5: .env file exposure -> extract credentials and test reuse
        if ftype in ("env_exposure", "env"):
            self.log_thought(f".env file discovered at {url}. Escalating to credential extraction, JWT forging, and DB credential reuse.")
            escalations.append(TestDecision(
                module_id="env_credential_reuse",
                target_url=url,
                target_host=host,
                priority=0,
                rationale=f".env at {url} likely contains DB_PASSWORD, JWT_SECRET, API_KEY; testing credential reuse on discovered login forms.",
                parameters={"artifact_url": url, "escalation_type": "env_credential_reuse"},
            ))

        # Escalation 6: CSV/PII data exposure -> identity correlation with login forms
        if ftype in ("data_exposure", "csv", "csv_export"):
            self.log_thought(f"CSV/PII data export discovered at {url}. Correlating identities with discovered login form fields.")
            escalations.append(TestDecision(
                module_id="identity_correlation",
                target_url=url,
                target_host=host,
                priority=1,
                rationale=f"CSV at {url} contains PII (usernames, NIMs, emails); cross-referencing with login form field names.",
                parameters={"artifact_url": url, "escalation_type": "csv_identity_correlation"},
            ))

        # Escalation 7: SSRF confirmed -> probe internal services through the vector
        if ftype in ("ssrf", "server_side_request_forgery"):
            self.log_thought(f"SSRF confirmed on {url} parameter '{param}'. Escalating to internal service discovery chain.")
            escalations.append(TestDecision(
                module_id="ssrf_internal_scan",
                target_url=url,
                target_host=host,
                priority=0,
                rationale=f"SSRF at {url} on '{param}'; probing internal services (MySQL, Redis, Cloud Metadata) through the vector.",
                parameters={"url": url, "parameter": param, "escalation_type": "ssrf_internal_discovery"},
            ))

        return escalations


# Module-level singleton
agentic_engine = AgenticDecisionEngine()
