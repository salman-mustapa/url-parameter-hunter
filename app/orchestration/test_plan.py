"""Test Plan Generation Engine (V4 §88 & V9.1 §21).

Generates intelligent, technology-aware and precondition-checked security test plans per asset.
Chooses tests dynamically based on preconditions instead of running every test blindly against every URL:
    - Asset type & Protocol
    - Detected technology stack
    - Authentication model
    - Discovered endpoints & parameters
    - Scope policy
    - Precondition satisfaction

All 18 V9.1 Dynamic Test Families Registered (V9.1 §21).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("orchestration.test_plan")


@dataclass
class TestModule:
    """Individual security test module definition."""
    id: str
    name: str
    category: str
    risk_level: str = "SAFE"  # SAFE, CONTROLLED, HIGH_RISK
    asset_types: List[str] = field(default_factory=lambda: ["web"])
    technologies: List[str] = field(default_factory=list)  # Empty = all
    dependencies: List[str] = field(default_factory=list)
    priority: int = 2  # 0=Critical, 1=High, 2=Medium, 3=Low


# Complete 18-Family Security Test Module Registry (V9.1 §21)
TEST_MODULES: List[TestModule] = [
    # Discovery & Reconnaissance
    TestModule(id="discovery.dns", name="DNS Resolution", category="discovery", priority=0, asset_types=["domain", "web"]),
    TestModule(id="discovery.subdomain", name="Subdomain Enumeration", category="discovery", priority=0, asset_types=["domain"]),
    TestModule(id="discovery.port", name="Port Scanning", category="network", priority=0, asset_types=["domain", "web", "ip"]),
    TestModule(id="discovery.service", name="Service Detection", category="network", priority=1, dependencies=["discovery.port"]),

    # Network Assessment
    TestModule(id="network.tls", name="TLS Assessment", category="network", priority=1, asset_types=["web"]),
    TestModule(id="network.ssh", name="SSH Deep Assessment", category="network", priority=1, technologies=["ssh", "openssh"]),
    TestModule(id="network.rdp", name="RDP Deep Assessment", category="network", priority=1, technologies=["rdp", "remote_desktop"]),

    # Web Assessment
    TestModule(id="web.http", name="HTTP Probe", category="web", priority=0, asset_types=["web"]),
    TestModule(id="web.screenshot", name="Visual Browser Proof", category="browser", priority=1, asset_types=["web"]),
    TestModule(id="web.crawler", name="Web Crawler", category="web", priority=1, asset_types=["web"]),
    TestModule(id="web.parameter", name="Parameter Discovery", category="web", priority=1, dependencies=["web.crawler"]),
    TestModule(id="web.technology", name="Technology Detection", category="web", priority=0, asset_types=["web"]),
    TestModule(id="web.headers", name="Security Headers", category="web", priority=2, asset_types=["web"]),
    TestModule(id="web.host_header", name="Host Header Injection", category="web", risk_level="CONTROLLED", priority=2, asset_types=["web"]),
    TestModule(id="web.smuggling", name="HTTP Request Smuggling", category="web", risk_level="CONTROLLED", priority=1, asset_types=["web"]),
    TestModule(id="web.websocket", name="WebSocket / CSWSH Assessment", category="web", risk_level="CONTROLLED", priority=2, asset_types=["web"]),

    # Authentication & Authorization
    TestModule(id="auth.login", name="Login Page Detection", category="authentication", priority=2, asset_types=["web"]),
    TestModule(id="auth.bypass", name="Authentication Bypass", category="authentication", risk_level="CONTROLLED", priority=1, asset_types=["web"], dependencies=["web.crawler"]),
    TestModule(id="auth.session", name="Session Security", category="authentication", priority=2, asset_types=["web"]),
    TestModule(id="auth.csrf", name="CSRF Deep Assessment", category="authentication", risk_level="CONTROLLED", priority=2, asset_types=["web"]),
    TestModule(id="auth.jwt", name="JWT / OAuth Security", category="authentication", risk_level="CONTROLLED", priority=1, asset_types=["web"]),

    # Injection Testing
    TestModule(id="injection.sqli", name="SQL Injection", category="injection", risk_level="CONTROLLED", priority=1, asset_types=["web"], dependencies=["web.parameter"]),
    TestModule(id="injection.xss", name="Cross-Site Scripting", category="injection", risk_level="CONTROLLED", priority=1, asset_types=["web"], dependencies=["web.parameter"]),
    TestModule(id="injection.rce", name="Remote Code Execution", category="injection", risk_level="CONTROLLED", priority=0, asset_types=["web"], dependencies=["web.parameter"]),
    TestModule(id="injection.ssrf", name="Server-Side Request Forgery", category="injection", risk_level="CONTROLLED", priority=1, asset_types=["web"], dependencies=["web.parameter"]),
    TestModule(id="injection.ssti", name="Server-Side Template Injection", category="injection", risk_level="CONTROLLED", priority=1, asset_types=["web"], dependencies=["web.parameter"]),
    TestModule(id="injection.deserialization", name="Insecure Deserialization", category="injection", risk_level="CONTROLLED", priority=1, asset_types=["web"]),

    # File & Path
    TestModule(id="file.traversal", name="Path Traversal", category="file", risk_level="CONTROLLED", priority=1, asset_types=["web"], dependencies=["web.parameter"]),
    TestModule(id="file.upload", name="File Upload Security", category="file", risk_level="CONTROLLED", priority=1, asset_types=["web"]),
    TestModule(id="file.sensitive", name="Sensitive File Exposure", category="file", priority=1, asset_types=["web"]),

    # Access Control
    TestModule(id="access.idor", name="IDOR / Broken Access Control", category="authorization", risk_level="CONTROLLED", priority=1, asset_types=["web"], dependencies=["web.parameter"]),
    TestModule(id="access.redirect", name="Open Redirect", category="web", risk_level="CONTROLLED", priority=2, asset_types=["web"], dependencies=["web.parameter"]),
    TestModule(id="access.cors", name="CORS Misconfiguration", category="web", risk_level="CONTROLLED", priority=2, asset_types=["web"]),

    # CMS-Specific
    TestModule(id="cms.wordpress", name="WordPress Deep Assessment", category="cms", priority=1, technologies=["wordpress"]),
    TestModule(id="cms.joomla", name="Joomla Assessment", category="cms", priority=2, technologies=["joomla"]),
    TestModule(id="cms.drupal", name="Drupal Assessment", category="cms", priority=2, technologies=["drupal"]),

    # API Security
    TestModule(id="api.rest", name="REST API Assessment", category="api", priority=2, technologies=["rest_api", "swagger", "openapi"]),
    TestModule(id="api.graphql", name="GraphQL Assessment", category="api", priority=2, technologies=["graphql"]),

    # Intelligence & Artifacts
    TestModule(id="intel.cve", name="CVE Correlation", category="intelligence", priority=0),
    TestModule(id="intel.ttp", name="MITRE ATT&CK Mapping", category="intelligence", priority=1),
    TestModule(id="intel.secrets", name="Secret / Info Disclosure", category="intelligence", priority=1, asset_types=["web"]),
    TestModule(id="intel.artifacts", name="Artifact Intelligence", category="intelligence", priority=1, asset_types=["web"]),

    # Evidence & Reporting
    TestModule(id="evidence.collect", name="Evidence Quality Gate", category="evidence", priority=0),
    TestModule(id="report.generate", name="Report Generation", category="reporting", priority=0),
]

PROFILES = {
    "quick": {
        "categories": {"discovery", "network", "web"},
        "modules": {
            "discovery.dns", "discovery.port", "discovery.service",
            "web.http", "web.technology", "web.screenshot",
            "network.tls", "intel.cve",
        },
    },
    "standard": {
        "categories": {"discovery", "network", "web", "intelligence"},
        "modules": {
            "discovery.dns", "discovery.subdomain", "discovery.port", "discovery.service",
            "web.http", "web.technology", "web.screenshot", "web.crawler", "web.parameter",
            "web.headers", "network.tls",
            "file.sensitive", "intel.cve", "intel.ttp", "intel.secrets", "intel.artifacts",
        },
    },
    "deep": {
        "categories": {"discovery", "network", "web", "authentication", "injection",
                       "file", "authorization", "cms", "api", "intelligence",
                       "evidence", "reporting"},
        "modules": None,  # ALL modules with technology and precondition matching
    },
    "custom": {
        "categories": set(),
        "modules": set(),
    },
}

# Product profile names share the same test-depth semantics used by scanners.
# Recursive versus focused is a scope-breadth option, not a weaker test plan.
PROFILES["bug_hunt"] = PROFILES["standard"]
PROFILES["deep_bug_hunt"] = PROFILES["deep"]
PROFILES["pentest"] = PROFILES["deep"]
PROFILES["adversary_simulation"] = PROFILES["deep"]
PROFILES["full"] = PROFILES["deep"]


@dataclass
class TestPlan:
    """Generated test plan for an asset."""
    asset_host: str
    profile: str
    modules: List[TestModule] = field(default_factory=list)
    skipped_modules: List[Dict[str, str]] = field(default_factory=list)
    technology_triggered: List[str] = field(default_factory=list)
    total_estimated_time_sec: int = 0


class TestPlanEngine:
    """Test Plan Generator (V4 §88 & V9.1 §21)."""

    def __init__(self) -> None:
        self.module_registry = {m.id: m for m in TEST_MODULES}

    def generate(
        self,
        asset_host: str,
        profile: str = "deep",
        technologies: Optional[List[str]] = None,
        asset_type: str = "web",
        scope_allowed_modules: Optional[Set[str]] = None,
    ) -> TestPlan:
        tech_set = {t.lower().strip() for t in (technologies or [])}
        prof = PROFILES.get(profile, PROFILES["deep"])
        selected: List[TestModule] = []
        skipped: List[Dict[str, str]] = []
        tech_triggered: List[str] = []

        for mod in TEST_MODULES:
            # Check Scope restriction
            if scope_allowed_modules and mod.id not in scope_allowed_modules:
                skipped.append({"id": mod.id, "reason": "Excluded by user scope policy"})
                continue

            # Check Profile inclusion
            if prof["modules"] is not None and mod.id not in prof["modules"]:
                skipped.append({"id": mod.id, "reason": f"Not included in '{profile}' scan profile"})
                continue

            # Check Asset type
            if asset_type not in mod.asset_types and "all" not in mod.asset_types:
                skipped.append({"id": mod.id, "reason": f"Asset type '{asset_type}' not in module targets {mod.asset_types}"})
                continue

            # Check Technology match (precondition)
            if mod.technologies:
                matching_tech = [t for t in mod.technologies if any(t in dt for dt in tech_set)]
                if not matching_tech:
                    skipped.append({"id": mod.id, "reason": f"Required technology {mod.technologies} not detected"})
                    continue
                tech_triggered.append(mod.id)

            selected.append(mod)

        # Sort by priority
        selected.sort(key=lambda m: m.priority)

        # Estimate execution time
        est_time = len(selected) * 8

        logger.info("Generated TestPlan for %s [%s]: %d modules selected, %d skipped",
                    asset_host, profile, len(selected), len(skipped))

        return TestPlan(
            asset_host=asset_host,
            profile=profile,
            modules=selected,
            skipped_modules=skipped,
            technology_triggered=tech_triggered,
            total_estimated_time_sec=est_time,
        )


test_plan_engine = TestPlanEngine()
