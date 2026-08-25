"""Security Knowledge Engine — Reference & Taxonomy Layer (V4 Architecture).

Consolidates security knowledge into a queryable reference layer:
- Vulnerability taxonomy (OWASP Top 10, CWE mappings)
- Technology-specific attack patterns
- Security invariant templates (business logic rules)
- Remediation recommendations database

This is NOT a hard limit on capability — the system can discover vulnerability
types not in this taxonomy. This is a reference and prioritization layer.

Integrates existing knowledge_base.py and cybersecurity_skills.py.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("intelligence.knowledge_engine")


class VulnerabilityCategory(str, Enum):
    INJECTION = "Injection"
    BROKEN_AUTH = "Broken Authentication"
    SENSITIVE_DATA = "Sensitive Data Exposure"
    XXE = "XML External Entities"
    BROKEN_ACCESS = "Broken Access Control"
    MISCONFIG = "Security Misconfiguration"
    XSS = "Cross-Site Scripting"
    DESERIALIZATION = "Insecure Deserialization"
    COMPONENTS = "Using Components with Known Vulnerabilities"
    LOGGING = "Insufficient Logging & Monitoring"
    SSRF = "Server-Side Request Forgery"
    BUSINESS_LOGIC = "Business Logic Flaws"
    API_SECURITY = "API Security"
    CRYPTOGRAPHIC = "Cryptographic Failures"


@dataclass
class VulnerabilityTemplate:
    """A known vulnerability type with metadata and testing guidance."""
    vuln_id: str
    name: str
    category: VulnerabilityCategory
    cwe_ids: List[int] = field(default_factory=list)
    owasp_category: str = ""
    description: str = ""
    detection_patterns: List[str] = field(default_factory=list)
    test_methodologies: List[str] = field(default_factory=list)
    remediation_guidance: str = ""
    severity_range: str = "MEDIUM-HIGH"
    tools: List[str] = field(default_factory=list)
    tags: Set[str] = field(default_factory=set)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vuln_id": self.vuln_id,
            "name": self.name,
            "category": self.category.value,
            "cwe_ids": self.cwe_ids,
            "owasp_category": self.owasp_category,
            "description": self.description,
            "detection_patterns": self.detection_patterns,
            "test_methodologies": self.test_methodologies,
            "remediation_guidance": self.remediation_guidance,
            "severity_range": self.severity_range,
            "tools": self.tools,
        }


@dataclass
class TechnologyAttackPattern:
    """A technology-specific attack pattern."""
    pattern_id: str
    technology: str
    attack_vector: str
    description: str
    test_steps: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    severity: str = "MEDIUM"
    cve_examples: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "technology": self.technology,
            "attack_vector": self.attack_vector,
            "description": self.description,
            "test_steps": self.test_steps,
            "indicators": self.indicators,
            "severity": self.severity,
        }


@dataclass
class SecurityInvariantTemplate:
    """A reusable security invariant template for business logic testing."""
    invariant_id: str
    name: str
    expression: str
    context: str  # e.g., "e-commerce", "banking", "authentication"
    description: str = ""
    violation_impact: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "invariant_id": self.invariant_id,
            "name": self.name,
            "expression": self.expression,
            "context": self.context,
            "description": self.description,
            "violation_impact": self.violation_impact,
        }


class SecurityKnowledgeEngine:
    """Queryable security knowledge reference layer.

    Provides vulnerability taxonomy, technology-specific attack patterns,
    and security invariant templates. This is a knowledge and reference layer,
    NOT a hard limit on system capability.
    """

    def __init__(self) -> None:
        self._vulnerability_templates: Dict[str, VulnerabilityTemplate] = {}
        self._attack_patterns: Dict[str, TechnologyAttackPattern] = {}
        self._invariant_templates: Dict[str, SecurityInvariantTemplate] = {}
        self._load_builtin_knowledge()

    # ---- Query API ----

    def get_vulnerability_template(self, vuln_id: str) -> Optional[VulnerabilityTemplate]:
        return self._vulnerability_templates.get(vuln_id)

    def find_vulnerabilities_by_category(self, category: VulnerabilityCategory) -> List[VulnerabilityTemplate]:
        return [v for v in self._vulnerability_templates.values() if v.category == category]

    def find_vulnerabilities_by_cwe(self, cwe_id: int) -> List[VulnerabilityTemplate]:
        return [v for v in self._vulnerability_templates.values() if cwe_id in v.cwe_ids]

    def find_vulnerabilities_by_tool(self, tool_name: str) -> List[VulnerabilityTemplate]:
        t = tool_name.lower()
        return [v for v in self._vulnerability_templates.values() if t in [x.lower() for x in v.tools]]

    def search_vulnerabilities(self, query: str) -> List[VulnerabilityTemplate]:
        q = query.lower()
        return [
            v for v in self._vulnerability_templates.values()
            if q in v.name.lower() or q in v.description.lower() or q in v.category.value.lower()
        ]

    def get_attack_patterns_for_technology(self, technology: str) -> List[TechnologyAttackPattern]:
        tech = technology.lower()
        return [p for p in self._attack_patterns.values() if tech in p.technology.lower()]

    def get_invariants_for_context(self, context: str) -> List[SecurityInvariantTemplate]:
        ctx = context.lower()
        return [i for i in self._invariant_templates.values() if ctx in i.context.lower()]

    def get_remediation(self, vuln_id: str) -> str:
        template = self._vulnerability_templates.get(vuln_id)
        if template:
            return template.remediation_guidance
        return "Consult OWASP guidelines and apply defense-in-depth principles."

    def get_summary(self) -> Dict[str, Any]:
        by_category: Dict[str, int] = {}
        for v in self._vulnerability_templates.values():
            by_category[v.category.value] = by_category.get(v.category.value, 0) + 1
        return {
            "total_vulnerability_templates": len(self._vulnerability_templates),
            "total_attack_patterns": len(self._attack_patterns),
            "total_invariant_templates": len(self._invariant_templates),
            "by_category": by_category,
        }

    # ---- Extensibility ----

    def register_vulnerability(self, template: VulnerabilityTemplate) -> None:
        self._vulnerability_templates[template.vuln_id] = template

    def register_attack_pattern(self, pattern: TechnologyAttackPattern) -> None:
        self._attack_patterns[pattern.pattern_id] = pattern

    def register_invariant(self, invariant: SecurityInvariantTemplate) -> None:
        self._invariant_templates[invariant.invariant_id] = invariant

    # ---- Built-in Knowledge ----

    def _load_builtin_knowledge(self) -> None:
        """Load built-in vulnerability taxonomy, attack patterns, and invariant templates."""
        self._load_vulnerability_taxonomy()
        self._load_technology_patterns()
        self._load_invariant_templates()

    def _load_vulnerability_taxonomy(self) -> None:
        vulns = [
            VulnerabilityTemplate("SQLI", "SQL Injection", VulnerabilityCategory.INJECTION,
                cwe_ids=[89], owasp_category="A03:2021",
                description="Untrusted data sent to SQL interpreter as part of a command or query",
                detection_patterns=["error-based", "time-based blind", "union-based", "stacked queries"],
                test_methodologies=["parameterized input fuzzing", "sleep timing", "union extraction", "error observation"],
                remediation_guidance="Use parameterized queries/prepared statements. Validate and sanitize all input. Apply least-privilege DB accounts.",
                tools=["sqli_validator"]),
            VulnerabilityTemplate("XSS", "Cross-Site Scripting", VulnerabilityCategory.XSS,
                cwe_ids=[79], owasp_category="A03:2021",
                description="Injection of client-side scripts into web pages",
                detection_patterns=["reflected", "stored", "DOM-based", "attribute injection"],
                test_methodologies=["tag injection", "event handler injection", "DOM sink analysis", "encoding bypass"],
                remediation_guidance="Context-sensitive output encoding. Use CSP headers. Sanitize HTML input with allow-list.",
                tools=["xss_validator"]),
            VulnerabilityTemplate("IDOR", "Insecure Direct Object Reference", VulnerabilityCategory.BROKEN_ACCESS,
                cwe_ids=[639, 284], owasp_category="A01:2021",
                description="Direct access to objects via user-controlled reference without authorization check",
                detection_patterns=["sequential ID enumeration", "UUID guessing", "parameter tampering"],
                test_methodologies=["horizontal privilege testing", "vertical privilege testing", "method asymmetry"],
                remediation_guidance="Implement server-side authorization checks for every object access. Use indirect references.",
                tools=["idor_validator", "idor_lifecycle_engine"]),
            VulnerabilityTemplate("SSRF", "Server-Side Request Forgery", VulnerabilityCategory.SSRF,
                cwe_ids=[918], owasp_category="A10:2021",
                description="Server makes requests to attacker-controlled URLs or internal resources",
                detection_patterns=["outbound request", "DNS rebinding", "redirect chain", "cloud metadata"],
                test_methodologies=["URL parameter injection", "header injection", "redirect following"],
                remediation_guidance="Validate and sanitize URLs server-side. Use allowlists for outbound requests. Block internal/metadata IPs.",
                tools=["ssrf_validator"]),
            VulnerabilityTemplate("SSTI", "Server-Side Template Injection", VulnerabilityCategory.INJECTION,
                cwe_ids=[1336], owasp_category="A03:2021",
                description="Injection into server-side template engines leading to RCE",
                detection_patterns=["math expression evaluation", "object traversal", "sandbox escape"],
                test_methodologies=["polyglot template probe", "engine fingerprinting", "expression evaluation"],
                remediation_guidance="Never pass user input directly to template engines. Use sandboxed rendering.",
                tools=["ssti_validator"]),
            VulnerabilityTemplate("RCE", "Remote Code Execution", VulnerabilityCategory.INJECTION,
                cwe_ids=[94, 78], owasp_category="A03:2021",
                description="Execution of arbitrary code on the server",
                detection_patterns=["command injection", "code injection", "deserialization"],
                test_methodologies=["OS command injection", "sleep/timing", "DNS exfiltration"],
                remediation_guidance="Never execute user-controlled input. Use allowlists. Sandbox execution environments.",
                tools=["rce_validator"]),
            VulnerabilityTemplate("AUTH_BYPASS", "Authentication Bypass", VulnerabilityCategory.BROKEN_AUTH,
                cwe_ids=[287, 306], owasp_category="A07:2021",
                description="Circumventing authentication mechanisms",
                detection_patterns=["default credentials", "session fixation", "2FA bypass", "JWT flaws"],
                test_methodologies=["credential testing", "token manipulation", "flow bypass"],
                remediation_guidance="Implement multi-factor auth. Use secure session management. Validate all authentication paths.",
                tools=["auth_bypass_validator", "jwt_mfa_engine"]),
            VulnerabilityTemplate("CORS_MISCONFIG", "CORS Misconfiguration", VulnerabilityCategory.MISCONFIG,
                cwe_ids=[942], owasp_category="A05:2021",
                description="Permissive Cross-Origin Resource Sharing allowing credential theft",
                detection_patterns=["wildcard origin", "null origin", "reflected origin"],
                test_methodologies=["origin header manipulation", "credentials flag testing"],
                remediation_guidance="Implement strict origin allowlists. Never reflect arbitrary origins with credentials.",
                tools=["cors_validator"]),
            VulnerabilityTemplate("CSRF", "Cross-Site Request Forgery", VulnerabilityCategory.BROKEN_ACCESS,
                cwe_ids=[352], owasp_category="A01:2021",
                description="Unauthorized state-changing requests via victim's authenticated session",
                detection_patterns=["missing CSRF token", "weak token validation", "cookie-only auth"],
                test_methodologies=["token omission", "token tampering", "cross-origin form submission"],
                remediation_guidance="Use anti-CSRF tokens. Implement SameSite cookie attributes. Verify origin/referer headers.",
                tools=["csrf_validator"]),
            VulnerabilityTemplate("PATH_TRAVERSAL", "Path Traversal", VulnerabilityCategory.BROKEN_ACCESS,
                cwe_ids=[22, 23], owasp_category="A01:2021",
                description="Accessing files outside intended directory via path manipulation",
                detection_patterns=["dot-dot-slash", "absolute path", "null byte"],
                test_methodologies=["directory traversal sequences", "encoding bypass", "OS-specific paths"],
                remediation_guidance="Canonicalize file paths. Use chroot/jail. Validate against allowlist.",
                tools=["path_traversal_validator"]),
            VulnerabilityTemplate("BUSINESS_LOGIC", "Business Logic Vulnerability", VulnerabilityCategory.BUSINESS_LOGIC,
                cwe_ids=[840], owasp_category="A04:2021",
                description="Flaws in business workflows allowing state manipulation",
                detection_patterns=["negative quantity", "price manipulation", "workflow skip", "race condition"],
                test_methodologies=["state mutation testing", "invariant violation", "sequence manipulation"],
                remediation_guidance="Validate business invariants server-side. Implement workflow state machines. Audit financial operations.",
                tools=["business_logic_validator"]),
            VulnerabilityTemplate("INFO_DISCLOSURE", "Information Disclosure", VulnerabilityCategory.SENSITIVE_DATA,
                cwe_ids=[200, 209], owasp_category="A01:2021",
                description="Exposure of sensitive information in responses, headers, or errors",
                detection_patterns=["stack trace", "debug mode", "verbose error", "internal IP"],
                test_methodologies=["error provocation", "header analysis", "response body inspection"],
                remediation_guidance="Disable debug modes. Use generic error pages. Strip sensitive headers.",
                tools=["info_disclosure_validator"]),
            VulnerabilityTemplate("OPEN_REDIRECT", "Open Redirect", VulnerabilityCategory.BROKEN_ACCESS,
                cwe_ids=[601], owasp_category="A01:2021",
                description="Redirect to attacker-controlled URL via parameter manipulation",
                detection_patterns=["url parameter redirect", "header redirect", "meta refresh"],
                test_methodologies=["URL parameter manipulation", "protocol bypass", "encoding bypass"],
                remediation_guidance="Validate redirect URLs against allowlist. Use indirect redirect references.",
                tools=["open_redirect_validator"]),
            VulnerabilityTemplate("HOST_HEADER", "Host Header Injection", VulnerabilityCategory.INJECTION,
                cwe_ids=[644], owasp_category="A05:2021",
                description="Host header manipulation for cache poisoning or password reset hijacking",
                detection_patterns=["host header reflection", "X-Forwarded-Host injection"],
                test_methodologies=["header injection", "password reset poisoning"],
                remediation_guidance="Validate Host header server-side. Use absolute URLs in password resets.",
                tools=["host_header_validator"]),
            VulnerabilityTemplate("DESERIALIZATION", "Insecure Deserialization", VulnerabilityCategory.DESERIALIZATION,
                cwe_ids=[502], owasp_category="A08:2021",
                description="Unsafe deserialization of untrusted data leading to RCE",
                detection_patterns=["serialized object in request", "pickle/yaml/xml deserialization"],
                test_methodologies=["gadget chain injection", "serialized payload crafting"],
                remediation_guidance="Never deserialize untrusted data. Use safe serialization formats (JSON). Implement integrity checks.",
                tools=["deserialization_validator"]),
            VulnerabilityTemplate("MASS_ASSIGNMENT", "Mass Assignment", VulnerabilityCategory.BROKEN_ACCESS,
                cwe_ids=[915], owasp_category="A01:2021",
                description="Overwriting protected object properties via unexpected request parameters",
                detection_patterns=["role escalation", "admin flag", "price override"],
                test_methodologies=["property overposting", "hidden field injection"],
                remediation_guidance="Use allowlists for bindable properties. Never bind request data directly to models.",
                tools=["idor_lifecycle_engine"]),
            VulnerabilityTemplate("JWT_FLAWS", "JWT Security Flaws", VulnerabilityCategory.BROKEN_AUTH,
                cwe_ids=[327, 347], owasp_category="A02:2021",
                description="JWT algorithm confusion, none algorithm, weak secrets, missing validation",
                detection_patterns=["alg:none", "RS256/HS256 confusion", "weak secret", "expired token acceptance"],
                test_methodologies=["algorithm switching", "claim tampering", "signature stripping"],
                remediation_guidance="Enforce algorithm validation. Use strong secrets. Validate all claims.",
                tools=["jwt_mfa_engine"]),
        ]
        for v in vulns:
            self._vulnerability_templates[v.vuln_id] = v

    def _load_technology_patterns(self) -> None:
        patterns = [
            TechnologyAttackPattern("wp_xmlrpc", "WordPress", "Brute Force via XML-RPC",
                "WordPress xmlrpc.php allows multi-call brute force bypassing login rate limiting",
                test_steps=["Check xmlrpc.php accessibility", "Send system.multicall with credentials", "Observe auth success"],
                indicators=["xmlrpc.php returns 200", "multicall method available"]),
            TechnologyAttackPattern("wp_rest_api", "WordPress", "REST API User Enumeration",
                "WordPress REST API exposes user information at /wp-json/wp/v2/users",
                test_steps=["Request /wp-json/wp/v2/users", "Observe user data in response"],
                indicators=["200 response with user objects"]),
            TechnologyAttackPattern("php_info", "PHP", "phpinfo() Exposure",
                "Exposed phpinfo() page leaks server configuration, paths, and environment variables",
                test_steps=["Check /phpinfo.php, /info.php", "Observe detailed server config"],
                indicators=["phpinfo() page detected"]),
            TechnologyAttackPattern("spring_actuator", "Spring Boot", "Actuator Endpoint Exposure",
                "Spring Boot actuator endpoints expose health, env, and debug information",
                test_steps=["Check /actuator/health", "Check /actuator/env", "Check /actuator/heapdump"],
                indicators=["actuator endpoints return data"], severity="HIGH"),
            TechnologyAttackPattern("express_debug", "Express.js/Node.js", "Debug Mode Information Leak",
                "Express debug mode or error handler leaks stack traces and source code",
                test_steps=["Trigger application error", "Observe stack trace in response"],
                indicators=["stack trace visible", "file paths exposed"]),
            TechnologyAttackPattern("django_debug", "Django", "DEBUG=True Information Leak",
                "Django DEBUG mode exposes detailed error pages with source code and settings",
                test_steps=["Request non-existent URL", "Observe Django debug error page"],
                indicators=["Django debug page detected", "settings visible"]),
            TechnologyAttackPattern("nginx_alias_traversal", "Nginx", "Alias Traversal",
                "Misconfigured Nginx alias directive allows path traversal",
                test_steps=["Append ../ to aliased path", "Observe file access outside intended directory"],
                indicators=["file content from parent directory"], severity="HIGH"),
            TechnologyAttackPattern("apache_server_status", "Apache", "Server-Status/Server-Info Exposure",
                "Apache mod_status or mod_info exposes server internals",
                test_steps=["Check /server-status", "Check /server-info"],
                indicators=["server status page accessible"]),
            TechnologyAttackPattern("graphql_introspection", "GraphQL", "Introspection Enabled",
                "GraphQL introspection reveals complete API schema",
                test_steps=["Send introspection query", "Map entire schema"],
                indicators=["__schema query returns results"]),
            TechnologyAttackPattern("docker_api", "Docker", "Exposed Docker API",
                "Unauthenticated Docker API allows container management and host escape",
                test_steps=["Check port 2375/2376", "Request /containers/json"],
                indicators=["Docker API responds"], severity="CRITICAL"),
        ]
        for p in patterns:
            self._attack_patterns[p.pattern_id] = p

    def _load_invariant_templates(self) -> None:
        invariants = [
            SecurityInvariantTemplate("inv_qty_positive", "Positive Quantity", "quantity > 0",
                "e-commerce", "Item quantities must always be positive",
                "Negative quantities can cause wallet credit and inventory inflation"),
            SecurityInvariantTemplate("inv_price_positive", "Non-Negative Price", "price >= 0",
                "e-commerce", "Prices must never be negative",
                "Negative prices cause credits instead of charges"),
            SecurityInvariantTemplate("inv_order_total", "Order Total Integrity", "order_total >= 0",
                "e-commerce", "Order totals must never be negative",
                "Negative totals create store credit"),
            SecurityInvariantTemplate("inv_balance_auth", "Balance Mutation Authorization",
                "balance_change requires authorized_transaction", "banking",
                "Account balance changes must be linked to authorized transactions",
                "Unauthorized balance manipulation enables theft"),
            SecurityInvariantTemplate("inv_ownership", "Object Ownership", "object.owner == authenticated_user",
                "access_control", "Users can only access objects they own",
                "Ownership bypass enables data theft"),
            SecurityInvariantTemplate("inv_workflow_order", "Workflow Step Order",
                "step_N requires step_N-1 completed", "workflow",
                "Workflow steps must be executed in order",
                "Step skipping bypasses payment or validation"),
            SecurityInvariantTemplate("inv_rate_limit", "Rate Limiting", "requests_per_minute <= threshold",
                "authentication", "Authentication endpoints must be rate-limited",
                "Missing rate limits enable brute force attacks"),
            SecurityInvariantTemplate("inv_session_binding", "Session-Identity Binding",
                "session.user_id == request.user_id", "authentication",
                "Sessions must be bound to the authenticated identity",
                "Session confusion enables account takeover"),
        ]
        for inv in invariants:
            self._invariant_templates[inv.invariant_id] = inv


security_knowledge_engine = SecurityKnowledgeEngine()
