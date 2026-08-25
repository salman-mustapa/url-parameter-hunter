"""Tool Registry — Deterministic Capability Layer (V4 Architecture).

Provides a structured, invocable tool system where each security tool:
- Has typed metadata: name, category, capabilities, preconditions, cost, risk_level
- Is deterministic: AI does not decide HOW tools work, only WHICH tool to invoke
- Wraps existing validators (SQLi, XSS, IDOR, etc.) as invocable tool entries
- Is extensible: new tools can be registered at runtime

Categories: RECON, CRAWL, FUZZ, PROBE, VALIDATE, EXPLOIT, EVIDENCE, REPORT
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set

logger = logging.getLogger("core.tool_registry")


class ToolCategory(str, Enum):
    RECON = "RECON"
    CRAWL = "CRAWL"
    FUZZ = "FUZZ"
    PROBE = "PROBE"
    VALIDATE = "VALIDATE"
    EXPLOIT = "EXPLOIT"
    EVIDENCE = "EVIDENCE"
    REPORT = "REPORT"


class ToolRiskLevel(str, Enum):
    SAFE = "SAFE"           # Read-only, no target state mutation
    LOW = "LOW"             # Minimal state mutation, easily reversible
    MEDIUM = "MEDIUM"       # Potential state change, requires authorization
    HIGH = "HIGH"           # Active exploitation, requires explicit authorization
    CRITICAL = "CRITICAL"   # Destructive potential, highest authorization needed


@dataclass
class ToolPrecondition:
    """A precondition that must be satisfied before a tool can execute."""
    name: str
    description: str
    check_fn: Optional[Callable[..., bool]] = None

    def is_satisfied(self, context: Dict[str, Any]) -> bool:
        if self.check_fn:
            try:
                return self.check_fn(context)
            except Exception:
                return False
        return True


@dataclass
class SecurityTool:
    """A registered, invocable security testing tool."""
    name: str
    category: ToolCategory
    description: str
    capabilities: List[str] = field(default_factory=list)
    preconditions: List[ToolPrecondition] = field(default_factory=list)
    cost: float = 1.0              # Request cost (1.0 = light HTTP, 5.0 = heavy scan)
    risk_level: ToolRiskLevel = ToolRiskLevel.SAFE
    timeout_seconds: float = 30.0
    tags: Set[str] = field(default_factory=set)
    # The actual invocable handler (async callable)
    handler: Optional[Callable[..., Coroutine]] = field(default=None, repr=False)
    enabled: bool = True

    def check_preconditions(self, context: Dict[str, Any]) -> List[str]:
        """Returns list of unmet precondition names. Empty = all met."""
        unmet = []
        for pc in self.preconditions:
            if not pc.is_satisfied(context):
                unmet.append(pc.name)
        return unmet

    async def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute the tool with given parameters."""
        if not self.enabled:
            return {"status": "error", "error": f"Tool '{self.name}' is disabled"}
        if not self.handler:
            return {"status": "error", "error": f"Tool '{self.name}' has no handler registered"}
        try:
            result = await self.handler(**kwargs)
            return {"status": "success", "result": result}
        except Exception as e:
            logger.error("Tool '%s' execution failed: %s", self.name, e)
            return {"status": "error", "error": str(e)}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category.value,
            "description": self.description,
            "capabilities": self.capabilities,
            "cost": self.cost,
            "risk_level": self.risk_level.value,
            "timeout_seconds": self.timeout_seconds,
            "tags": sorted(self.tags),
            "enabled": self.enabled,
            "preconditions": [p.name for p in self.preconditions],
            "has_handler": self.handler is not None,
        }


class ToolRegistry:
    """Central registry for all security testing tools.

    Tools are deterministic — AI does not decide HOW tools work,
    only WHICH tool to invoke and with what parameters.
    """

    def __init__(self) -> None:
        self._tools: Dict[str, SecurityTool] = {}
        self._register_builtin_tools()

    def register(self, tool: SecurityTool) -> None:
        """Register a new security tool."""
        self._tools[tool.name] = tool
        logger.info("Registered tool: %s [%s]", tool.name, tool.category.value)

    def unregister(self, name: str) -> bool:
        """Unregister a tool by name."""
        if name in self._tools:
            del self._tools[name]
            return True
        return False

    def get(self, name: str) -> Optional[SecurityTool]:
        """Get a tool by name."""
        return self._tools.get(name)

    def find_by_category(self, category: ToolCategory) -> List[SecurityTool]:
        """Find all tools in a given category."""
        return [t for t in self._tools.values() if t.category == category and t.enabled]

    def find_by_capability(self, capability: str) -> List[SecurityTool]:
        """Find tools that declare a specific capability."""
        cap_lower = capability.lower()
        return [
            t for t in self._tools.values()
            if t.enabled and any(cap_lower in c.lower() for c in t.capabilities)
        ]

    def find_by_tags(self, tags: Set[str]) -> List[SecurityTool]:
        """Find tools matching any of the given tags."""
        return [t for t in self._tools.values() if t.enabled and t.tags & tags]

    def find_for_vulnerability_type(self, vuln_type: str) -> List[SecurityTool]:
        """Find tools applicable to a given vulnerability type."""
        vt = vuln_type.lower()
        return [
            t for t in self._tools.values()
            if t.enabled and (
                vt in t.name.lower()
                or any(vt in c.lower() for c in t.capabilities)
                or vt in {tag.lower() for tag in t.tags}
            )
        ]

    def list_tools(self, enabled_only: bool = True) -> List[SecurityTool]:
        """List all registered tools."""
        if enabled_only:
            return [t for t in self._tools.values() if t.enabled]
        return list(self._tools.values())

    def get_summary(self) -> Dict[str, Any]:
        """Returns structured summary of all registered tools."""
        tools = self.list_tools(enabled_only=False)
        by_category: Dict[str, int] = {}
        for t in tools:
            by_category[t.category.value] = by_category.get(t.category.value, 0) + 1
        return {
            "total_tools": len(tools),
            "enabled_tools": sum(1 for t in tools if t.enabled),
            "by_category": by_category,
            "tools": [t.to_dict() for t in tools],
        }

    def _register_builtin_tools(self) -> None:
        """Register built-in security tools wrapping existing validators."""
        builtin_defs = [
            # RECON tools
            ("subdomain_enumeration", ToolCategory.RECON, "Passive subdomain discovery via DNS, crt.sh, and wordlists",
             ["subdomain_discovery", "dns_enumeration"], ToolRiskLevel.SAFE, 2.0, {"recon", "dns", "subdomain"}),
            ("port_scanner", ToolCategory.RECON, "TCP/UDP port scanning and service detection",
             ["port_scan", "service_detection", "banner_grab"], ToolRiskLevel.LOW, 3.0, {"recon", "network", "port"}),
            ("technology_fingerprint", ToolCategory.RECON, "Web technology stack identification",
             ["tech_detection", "cms_detection", "framework_detection"], ToolRiskLevel.SAFE, 1.0, {"recon", "technology"}),

            # CRAWL tools
            ("web_crawler", ToolCategory.CRAWL, "Deep web crawling with JS rendering and endpoint discovery",
             ["url_discovery", "js_parsing", "form_discovery", "api_discovery"], ToolRiskLevel.SAFE, 3.0, {"crawl", "web", "endpoint"}),
            ("js_analyzer", ToolCategory.CRAWL, "JavaScript source analysis for secrets, endpoints, and API schemas",
             ["js_analysis", "secret_detection", "api_schema_discovery"], ToolRiskLevel.SAFE, 2.0, {"crawl", "javascript", "secrets"}),
            ("directory_fuzzer", ToolCategory.FUZZ, "Directory and sensitive file discovery",
             ["directory_scan", "sensitive_file_discovery", "backup_detection"], ToolRiskLevel.LOW, 2.0, {"fuzz", "directory", "files"}),

            # VALIDATE tools (wrapping existing validators)
            ("sqli_validator", ToolCategory.VALIDATE, "SQL injection detection and validation",
             ["sqli", "error_based_sqli", "blind_sqli", "time_based_sqli", "union_sqli"], ToolRiskLevel.MEDIUM, 3.0, {"sqli", "injection", "database"}),
            ("xss_validator", ToolCategory.VALIDATE, "Cross-site scripting detection and validation",
             ["reflected_xss", "stored_xss", "dom_xss"], ToolRiskLevel.LOW, 2.0, {"xss", "injection", "client_side"}),
            ("idor_validator", ToolCategory.VALIDATE, "Insecure direct object reference testing",
             ["idor", "authorization", "access_control", "object_reference"], ToolRiskLevel.MEDIUM, 2.0, {"idor", "authorization"}),
            ("ssrf_validator", ToolCategory.VALIDATE, "Server-side request forgery detection",
             ["ssrf", "internal_access", "cloud_metadata"], ToolRiskLevel.MEDIUM, 3.0, {"ssrf", "server_side"}),
            ("ssti_validator", ToolCategory.VALIDATE, "Server-side template injection detection",
             ["ssti", "template_injection", "rce_via_template"], ToolRiskLevel.HIGH, 3.0, {"ssti", "injection", "rce"}),
            ("rce_validator", ToolCategory.VALIDATE, "Remote code execution detection and validation",
             ["rce", "command_injection", "os_command"], ToolRiskLevel.CRITICAL, 4.0, {"rce", "injection", "critical"}),
            ("path_traversal_validator", ToolCategory.VALIDATE, "Path traversal / LFI / RFI detection",
             ["lfi", "rfi", "path_traversal", "file_read"], ToolRiskLevel.HIGH, 2.0, {"path_traversal", "file_access"}),
            ("cors_validator", ToolCategory.VALIDATE, "CORS misconfiguration detection",
             ["cors", "origin_bypass", "credential_theft"], ToolRiskLevel.SAFE, 1.0, {"cors", "misconfiguration"}),
            ("csrf_validator", ToolCategory.VALIDATE, "Cross-site request forgery detection",
             ["csrf", "state_changing", "token_validation"], ToolRiskLevel.LOW, 2.0, {"csrf", "session"}),
            ("open_redirect_validator", ToolCategory.VALIDATE, "Open redirect detection",
             ["open_redirect", "url_redirect"], ToolRiskLevel.SAFE, 1.0, {"redirect", "phishing"}),
            ("host_header_validator", ToolCategory.VALIDATE, "Host header injection detection",
             ["host_header", "password_reset_poisoning"], ToolRiskLevel.LOW, 1.0, {"host_header", "injection"}),
            ("auth_bypass_validator", ToolCategory.VALIDATE, "Authentication bypass detection",
             ["auth_bypass", "login_bypass", "2fa_bypass", "session_fixation"], ToolRiskLevel.HIGH, 3.0, {"authentication", "bypass"}),
            ("bypass_403_validator", ToolCategory.VALIDATE, "403 bypass and access control testing",
             ["403_bypass", "path_normalization", "verb_tampering"], ToolRiskLevel.MEDIUM, 2.0, {"bypass", "access_control"}),
            ("file_upload_validator", ToolCategory.VALIDATE, "File upload vulnerability testing",
             ["file_upload", "unrestricted_upload", "web_shell"], ToolRiskLevel.HIGH, 3.0, {"upload", "file", "rce"}),
            ("request_smuggling_validator", ToolCategory.VALIDATE, "HTTP request smuggling detection",
             ["request_smuggling", "http_desync", "cl_te"], ToolRiskLevel.HIGH, 4.0, {"smuggling", "http"}),
            ("graphql_validator", ToolCategory.VALIDATE, "GraphQL introspection and injection testing",
             ["graphql", "introspection", "batch_query"], ToolRiskLevel.MEDIUM, 2.0, {"graphql", "api"}),
            ("websocket_validator", ToolCategory.VALIDATE, "WebSocket security testing",
             ["websocket", "ws_injection", "origin_check"], ToolRiskLevel.MEDIUM, 2.0, {"websocket", "realtime"}),
            ("deserialization_validator", ToolCategory.VALIDATE, "Insecure deserialization detection",
             ["deserialization", "object_injection", "pickle", "yaml_load"], ToolRiskLevel.CRITICAL, 4.0, {"deserialization", "rce"}),
            ("nosqli_validator", ToolCategory.VALIDATE, "NoSQL injection detection",
             ["nosqli", "mongodb_injection", "json_injection"], ToolRiskLevel.MEDIUM, 2.0, {"nosqli", "injection", "database"}),
            ("ldap_xpath_validator", ToolCategory.VALIDATE, "LDAP and XPath injection detection",
             ["ldap_injection", "xpath_injection"], ToolRiskLevel.MEDIUM, 2.0, {"ldap", "xpath", "injection"}),
            ("brute_force_validator", ToolCategory.VALIDATE, "Brute force and credential stuffing detection",
             ["brute_force", "rate_limiting", "account_lockout"], ToolRiskLevel.MEDIUM, 3.0, {"brute_force", "authentication"}),
            ("info_disclosure_validator", ToolCategory.VALIDATE, "Information disclosure and sensitive data exposure",
             ["info_disclosure", "error_leak", "stack_trace", "debug_page"], ToolRiskLevel.SAFE, 1.0, {"info_disclosure", "data_leak"}),

            # Advanced engines
            ("jwt_mfa_engine", ToolCategory.VALIDATE, "JWT security and 2FA/MFA bypass testing",
             ["jwt", "alg_none", "algorithm_confusion", "2fa_bypass", "totp_abuse"], ToolRiskLevel.HIGH, 3.0, {"jwt", "mfa", "authentication"}),
            ("idor_lifecycle_engine", ToolCategory.VALIDATE, "IDOR deep lifecycle and mass assignment testing",
             ["idor_lifecycle", "mass_assignment", "ownership_change", "asymmetric_methods"], ToolRiskLevel.HIGH, 3.0, {"idor", "mass_assignment"}),
            ("business_logic_validator", ToolCategory.VALIDATE, "Business logic vulnerability testing",
             ["business_logic", "workflow_bypass", "state_manipulation", "price_manipulation"], ToolRiskLevel.HIGH, 3.0, {"business_logic", "workflow"}),
            ("sensitive_files_scanner", ToolCategory.VALIDATE, "Sensitive file and backup discovery",
             ["sensitive_files", "backup_files", "config_files", "database_dumps"], ToolRiskLevel.SAFE, 2.0, {"files", "sensitive", "backup"}),
            ("cve_exploiter", ToolCategory.EXPLOIT, "Known CVE exploitation and validation",
             ["cve", "known_vulnerability", "exploit_db"], ToolRiskLevel.HIGH, 4.0, {"cve", "exploit"}),

            # EVIDENCE tools
            ("screenshot_tool", ToolCategory.EVIDENCE, "Browser screenshot capture for evidence",
             ["screenshot", "visual_evidence"], ToolRiskLevel.SAFE, 2.0, {"evidence", "screenshot"}),
            ("poc_generator", ToolCategory.EVIDENCE, "Proof of concept generation",
             ["poc", "reproduction", "curl_command"], ToolRiskLevel.SAFE, 1.0, {"evidence", "poc"}),

            # REPORT tools
            ("report_generator", ToolCategory.REPORT, "Professional security report generation",
             ["report", "pdf", "markdown", "executive_summary"], ToolRiskLevel.SAFE, 1.0, {"report", "output"}),
        ]

        for name, category, description, capabilities, risk, cost, tags in builtin_defs:
            self.register(SecurityTool(
                name=name,
                category=category,
                description=description,
                capabilities=capabilities,
                risk_level=risk,
                cost=cost,
                tags=tags,
            ))


tool_registry = ToolRegistry()
