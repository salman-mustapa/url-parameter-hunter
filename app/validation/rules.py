from __future__ import annotations

from typing import Any, Dict, List


class RuleRegistry:
    """Security Test Rule Registry (§66, §92).
    Standardized capability rules with preconditions, expected results, confidence, and remediation.
    """

    RULES = [
        {
            "rule_id": "sec.headers.missing_csp",
            "name": "Missing Content-Security-Policy (CSP)",
            "category": "security_headers",
            "severity": "LOW",
            "cwe_id": "CWE-1021",
            "description": "Content-Security-Policy header is missing, leaving the application susceptible to cross-site scripting and data injection.",
            "remediation": "Implement a strong Content-Security-Policy header specifying allowed script, style, and frame sources.",
        },
        {
            "rule_id": "sec.headers.missing_hsts",
            "name": "Strict-Transport-Security (HSTS) Not Enforced",
            "category": "security_headers",
            "severity": "LOW",
            "cwe_id": "CWE-319",
            "description": "Strict-Transport-Security header is not set on HTTPS endpoint, allowing potential downgrade / MITM attacks.",
            "remediation": "Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' on all HTTPS responses.",
        },
        {
            "rule_id": "sec.cors.wildcard_origin",
            "name": "Overly Permissive CORS Policy",
            "category": "cors",
            "severity": "MEDIUM",
            "cwe_id": "CWE-942",
            "description": "Access-Control-Allow-Origin header is set to '*' or reflects arbitrary origin with credentials allowed.",
            "remediation": "Restrict CORS origins to trusted, explicit domains and avoid wildcards when handling authenticated sessions.",
        },
        {
            "rule_id": "sec.info.version_banner",
            "name": "Detailed Server Information Disclosure",
            "category": "information_disclosure",
            "severity": "LOW",
            "cwe_id": "CWE-200",
            "description": "Web server discloses exact vendor and operating system version in Server or X-Powered-By response headers.",
            "remediation": "Disable server tokens in web server configuration (e.g. server_tokens off in Nginx, ServerTokens Prod in Apache).",
        },
        {
            "rule_id": "sec.auth.cookie_missing_secure",
            "name": "Session Cookie Missing Secure / HttpOnly Flag",
            "category": "authentication",
            "severity": "MEDIUM",
            "cwe_id": "CWE-614",
            "description": "Sensitive session cookie is set without Secure or HttpOnly attribute.",
            "remediation": "Ensure all session and authentication cookies include Secure, HttpOnly, and SameSite=Lax/Strict flags.",
        },
    ]

    @classmethod
    def get_rule(cls, rule_id: str) -> Dict[str, Any]:
        for r in cls.RULES:
            if r["rule_id"] == rule_id:
                return r
        return {
            "rule_id": rule_id,
            "name": rule_id,
            "category": "general",
            "severity": "INFO",
            "cwe_id": "CWE-200",
            "description": "Security observation detected.",
            "remediation": "Review application configuration.",
        }
