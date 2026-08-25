"""WordPress Deep Security Assessment Module (V5 §18, V4 §75-77).

Comprehensive WordPress security testing:
- Version detection and CVE correlation
- Plugin inventory and vulnerability matching
- Theme enumeration
- REST API exposure assessment
- XML-RPC assessment
- User enumeration detection
- Login security assessment
- Configuration exposure checks
- Directory listing checks
- Debug mode detection
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import httpx

logger = logging.getLogger("intelligence.wordpress")

# Known vulnerable/sensitive WordPress paths
WP_SENSITIVE_PATHS = [
    "/wp-config.php.bak",
    "/wp-config.php~",
    "/wp-config.php.old",
    "/wp-config.php.save",
    "/wp-config.php.swp",
    "/wp-config.php.txt",
    "/.wp-config.php.swp",
    "/wp-config.bak",
    "/backup/wp-config.php",
]

WP_DIRECTORY_PATHS = [
    "/wp-content/uploads/",
    "/wp-content/plugins/",
    "/wp-content/themes/",
    "/wp-includes/",
    "/wp-content/backup-db/",
    "/wp-content/backups/",
    "/wp-content/debug.log",
]

WP_REST_ENDPOINTS = [
    "/wp-json/",
    "/wp-json/wp/v2/users",
    "/wp-json/wp/v2/posts",
    "/wp-json/wp/v2/pages",
    "/wp-json/wp/v2/categories",
    "/wp-json/wp/v2/settings",
]

# User enumeration paths
WP_USER_ENUM_PATHS = [
    "/?author=1",
    "/?author=2",
    "/?author=3",
    "/wp-json/wp/v2/users",
]


class WordPressIntelligence:
    """WordPress Deep Security Intelligence Module (V5 §18, V4 §75-77).

    Implements full WordPress assessment pipeline:
        WordPress detection → Version indicators → Theme → Plugins
        → REST API → Login endpoints → XML-RPC → Known exposed files
        → CVE correlation → Controlled validation → Evidence
    """

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout

    @classmethod
    def analyze_html_and_headers(cls, html: str, headers: Dict[str, str]) -> Dict[str, Any]:
        """Basic static analysis of HTML and headers for WordPress indicators."""
        result = {
            "is_wordpress": False,
            "version": None,
            "theme": None,
            "plugins": [],
            "rest_api_exposed": False,
            "xmlrpc_exposed": False,
            "findings": [],
        }

        # 1. Detection via generator tag
        gen_match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s*([\d\.]*)["\']', html, re.I)
        if gen_match:
            result["is_wordpress"] = True
            result["version"] = gen_match.group(1) or "Detected"

        # 2. Detection via wp-content / wp-includes
        if "/wp-content/" in html or "/wp-includes/" in html:
            result["is_wordpress"] = True

        # 3. Detection via wp-login / wp-admin references
        if "wp-login.php" in html or "wp-admin" in html:
            result["is_wordpress"] = True

        # 4. Detect Theme
        theme_match = re.search(r'/wp-content/themes/([^/\s"\'\?]+)', html)
        if theme_match:
            result["theme"] = theme_match.group(1)

        # 5. Detect Plugins
        plugin_matches = set(re.findall(r'/wp-content/plugins/([^/\s"\'\?]+)', html))
        result["plugins"] = sorted(list(plugin_matches))

        # 6. Detect REST API link
        if "wp-json" in html or any("wp-json" in h for h in headers.values()):
            result["rest_api_exposed"] = True

        # 7. Detect XML-RPC link header
        if any("xmlrpc" in h.lower() for h in headers.values()):
            result["xmlrpc_exposed"] = True

        # 8. Plugin version detection
        plugin_versions = {}
        for plugin in result["plugins"]:
            ver_match = re.search(
                rf'/wp-content/plugins/{re.escape(plugin)}/[^"\']*\?ver=([0-9][0-9.]*)',
                html,
            )
            if ver_match:
                plugin_versions[plugin] = ver_match.group(1)
        result["plugin_versions"] = plugin_versions

        # 9. Theme version detection
        if result["theme"]:
            theme_ver_match = re.search(
                rf'/wp-content/themes/{re.escape(result["theme"])}/[^"\']*\?ver=([0-9][0-9.]*)',
                html,
            )
            if theme_ver_match:
                result["theme_version"] = theme_ver_match.group(1)

        # 10. Version disclosure finding
        if result["version"] and result["version"] != "Detected":
            result["findings"].append({
                "title": f"WordPress Version Disclosed ({result['version']})",
                "severity": "LOW",
                "cwe": "CWE-200",
                "description": f"WordPress version {result['version']} is publicly visible in HTML meta tags.",
                "evidence_level": "E1",
            })

        return result

    async def deep_assess(
        self,
        base_url: str,
        wp_info: Dict[str, Any],
        *,
        headers: Optional[dict] = None,
    ) -> Dict[str, Any]:
        """Perform deep WordPress security assessment (V4 §75-77).

        Runs after basic detection confirms WordPress is present.
        """
        findings: List[Dict[str, Any]] = list(wp_info.get("findings", []))
        evidence: List[Dict[str, Any]] = []

        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True, verify=False
        ) as client:
            # 1. REST API User Enumeration
            rest_findings = await self._check_rest_api(client, base_url, headers)
            findings.extend(rest_findings)

            # 2. XML-RPC Assessment
            xmlrpc_findings = await self._check_xmlrpc(client, base_url, headers)
            findings.extend(xmlrpc_findings)

            # 3. User Enumeration via Author Archives
            user_findings = await self._check_user_enumeration(client, base_url, headers)
            findings.extend(user_findings)

            # 4. Configuration File Exposure
            config_findings = await self._check_config_exposure(client, base_url, headers)
            findings.extend(config_findings)

            # 5. Directory Listing Checks
            dir_findings = await self._check_directory_listing(client, base_url, headers)
            findings.extend(dir_findings)

            # 6. Debug Log Exposure
            debug_findings = await self._check_debug_log(client, base_url, headers)
            findings.extend(debug_findings)

            # 7. Login Security Assessment
            login_findings = await self._check_login_security(client, base_url, headers)
            findings.extend(login_findings)

            # 8. Plugin CVE Correlation
            plugin_cve_findings = self._correlate_plugin_cves(wp_info)
            findings.extend(plugin_cve_findings)

        return {
            **wp_info,
            "findings": findings,
            "deep_assessed": True,
            "assessment_complete": True,
        }

    async def _check_rest_api(
        self, client: httpx.AsyncClient, base_url: str, headers: Optional[dict]
    ) -> List[Dict[str, Any]]:
        """Check REST API exposure and user enumeration."""
        findings = []

        # Check main REST API endpoint
        try:
            resp = await client.get(urljoin(base_url, "/wp-json/"), headers=headers or {})
            if resp.status_code == 200 and "wp/v2" in resp.text:
                findings.append({
                    "title": "WordPress REST API Publicly Accessible",
                    "severity": "LOW",
                    "cwe": "CWE-200",
                    "description": "WordPress REST API is publicly accessible without authentication. This exposes site metadata and content structure.",
                    "evidence_level": "E2",
                    "evidence": {"status_code": resp.status_code, "endpoint": "/wp-json/"},
                })
        except Exception:
            pass

        # Check user enumeration via REST API
        try:
            resp = await client.get(urljoin(base_url, "/wp-json/wp/v2/users"), headers=headers or {})
            if resp.status_code == 200:
                try:
                    users = resp.json()
                    if isinstance(users, list) and len(users) > 0:
                        user_names = [u.get("name", "?") for u in users[:5]]
                        findings.append({
                            "title": f"WordPress User Enumeration via REST API ({len(users)} users)",
                            "severity": "MEDIUM",
                            "cwe": "CWE-200",
                            "description": f"User accounts enumerable via REST API: {', '.join(user_names)}",
                            "evidence_level": "E3",
                            "evidence": {
                                "status_code": resp.status_code,
                                "endpoint": "/wp-json/wp/v2/users",
                                "user_count": len(users),
                                "sample_users": user_names,
                            },
                        })
                except Exception:
                    pass
        except Exception:
            pass

        return findings

    async def _check_xmlrpc(
        self, client: httpx.AsyncClient, base_url: str, headers: Optional[dict]
    ) -> List[Dict[str, Any]]:
        """Check XML-RPC exposure."""
        findings = []
        try:
            xmlrpc_url = urljoin(base_url, "/xmlrpc.php")
            # Send a safe system.listMethods call
            payload = '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'
            resp = await client.post(
                xmlrpc_url,
                content=payload,
                headers={**(headers or {}), "Content-Type": "text/xml"},
            )

            if resp.status_code == 200 and "methodResponse" in resp.text:
                methods_count = resp.text.count("<value>")
                has_multicall = "system.multicall" in resp.text
                has_pingback = "pingback" in resp.text

                severity = "MEDIUM" if has_multicall else "LOW"
                desc_parts = [f"XML-RPC is accessible ({methods_count} methods exposed)"]
                if has_multicall:
                    desc_parts.append("system.multicall enabled (amplification attack vector)")
                if has_pingback:
                    desc_parts.append("pingback enabled (SSRF/DDoS vector)")

                findings.append({
                    "title": "WordPress XML-RPC Exposed",
                    "severity": severity,
                    "cwe": "CWE-16",
                    "description": ". ".join(desc_parts),
                    "evidence_level": "E2",
                    "evidence": {
                        "status_code": resp.status_code,
                        "endpoint": "/xmlrpc.php",
                        "methods_count": methods_count,
                        "multicall_enabled": has_multicall,
                        "pingback_enabled": has_pingback,
                    },
                })
        except Exception:
            pass
        return findings

    async def _check_user_enumeration(
        self, client: httpx.AsyncClient, base_url: str, headers: Optional[dict]
    ) -> List[Dict[str, Any]]:
        """Check user enumeration via author archives."""
        findings = []
        for path in ["/?author=1", "/?author=2"]:
            try:
                resp = await client.get(urljoin(base_url, path), headers=headers or {})
                if resp.status_code == 200:
                    # Check for author name in URL or title
                    author_match = re.search(r"/author/([^/\"']+)", str(resp.url))
                    if author_match:
                        findings.append({
                            "title": f"WordPress User Enumeration via Author Archives",
                            "severity": "LOW",
                            "cwe": "CWE-200",
                            "description": f"Author '{author_match.group(1)}' enumerated via /?author= parameter redirect.",
                            "evidence_level": "E2",
                            "evidence": {
                                "endpoint": path,
                                "redirected_to": str(resp.url),
                                "author_slug": author_match.group(1),
                            },
                        })
                        break  # One confirmed is enough
            except Exception:
                pass
        return findings

    async def _check_config_exposure(
        self, client: httpx.AsyncClient, base_url: str, headers: Optional[dict]
    ) -> List[Dict[str, Any]]:
        """Check for exposed WordPress configuration backup files."""
        findings = []
        for path in WP_SENSITIVE_PATHS:
            try:
                resp = await client.get(urljoin(base_url, path), headers=headers or {})
                if resp.status_code == 200 and len(resp.text) > 50:
                    # Look for WP config indicators
                    if any(kw in resp.text for kw in ["DB_NAME", "DB_USER", "DB_PASSWORD", "table_prefix"]):
                        findings.append({
                            "title": f"WordPress Configuration Backup Exposed ({path})",
                            "severity": "CRITICAL",
                            "cwe": "CWE-200",
                            "description": f"WordPress configuration file accessible at {path}. Contains database credentials and security keys.",
                            "evidence_level": "E3",
                            "evidence": {
                                "status_code": resp.status_code,
                                "path": path,
                                "contains_credentials": True,
                                "response_hash": hashlib.sha256(resp.text.encode()).hexdigest()[:16],
                            },
                        })
                        break  # One critical finding is enough
            except Exception:
                pass
        return findings

    async def _check_directory_listing(
        self, client: httpx.AsyncClient, base_url: str, headers: Optional[dict]
    ) -> List[Dict[str, Any]]:
        """Check for directory listing on WordPress directories."""
        findings = []
        for path in WP_DIRECTORY_PATHS[:4]:  # Bounded
            if path.endswith(".log"):
                continue  # Handled separately
            try:
                resp = await client.get(urljoin(base_url, path), headers=headers or {})
                if resp.status_code == 200:
                    body = resp.text.lower()
                    if "index of" in body or "directory listing" in body or "<pre>" in body:
                        findings.append({
                            "title": f"WordPress Directory Listing Enabled ({path})",
                            "severity": "MEDIUM",
                            "cwe": "CWE-548",
                            "description": f"Directory listing enabled at {path}. Exposes internal file structure.",
                            "evidence_level": "E2",
                            "evidence": {
                                "status_code": resp.status_code,
                                "path": path,
                                "response_hash": hashlib.sha256(resp.text.encode()).hexdigest()[:16],
                            },
                        })
            except Exception:
                pass
        return findings

    async def _check_debug_log(
        self, client: httpx.AsyncClient, base_url: str, headers: Optional[dict]
    ) -> List[Dict[str, Any]]:
        """Check for exposed WordPress debug log."""
        findings = []
        try:
            resp = await client.get(urljoin(base_url, "/wp-content/debug.log"), headers=headers or {})
            if resp.status_code == 200 and len(resp.text) > 100:
                if any(kw in resp.text for kw in ["PHP Fatal", "PHP Warning", "PHP Notice", "Stack trace"]):
                    findings.append({
                        "title": "WordPress Debug Log Exposed (debug.log)",
                        "severity": "HIGH",
                        "cwe": "CWE-532",
                        "description": "WordPress debug.log is publicly accessible. May contain sensitive internal paths, database errors, and stack traces.",
                        "evidence_level": "E3",
                        "evidence": {
                            "status_code": resp.status_code,
                            "path": "/wp-content/debug.log",
                            "file_size": len(resp.text),
                            "response_hash": hashlib.sha256(resp.text.encode()).hexdigest()[:16],
                        },
                    })
        except Exception:
            pass
        return findings

    async def _check_login_security(
        self, client: httpx.AsyncClient, base_url: str, headers: Optional[dict]
    ) -> List[Dict[str, Any]]:
        """Assess WordPress login page security."""
        findings = []
        try:
            resp = await client.get(urljoin(base_url, "/wp-login.php"), headers=headers or {})
            if resp.status_code == 200 and "wp-login" in resp.text.lower():
                body = resp.text

                # Check if login is publicly accessible
                findings.append({
                    "title": "WordPress Login Page Publicly Accessible",
                    "severity": "INFO",
                    "cwe": "CWE-16",
                    "description": "WordPress login page is accessible from the internet.",
                    "evidence_level": "E1",
                    "evidence": {
                        "status_code": resp.status_code,
                        "endpoint": "/wp-login.php",
                    },
                })

                # Check for CAPTCHA / rate limiting indicators
                has_captcha = any(
                    kw in body.lower()
                    for kw in ["captcha", "recaptcha", "hcaptcha", "turnstile"]
                )
                if not has_captcha:
                    findings.append({
                        "title": "WordPress Login Without CAPTCHA Protection",
                        "severity": "LOW",
                        "cwe": "CWE-307",
                        "description": "WordPress login page does not appear to have CAPTCHA protection, making it susceptible to brute force attacks.",
                        "evidence_level": "E1",
                    })

                # Check registration
                if "register" in body.lower() or "registration" in body.lower():
                    findings.append({
                        "title": "WordPress User Registration Open",
                        "severity": "INFO",
                        "cwe": "CWE-16",
                        "description": "WordPress user registration appears to be enabled.",
                        "evidence_level": "E1",
                    })

        except Exception:
            pass
        return findings

    def _correlate_plugin_cves(self, wp_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Correlate detected plugins with known CVE patterns."""
        findings = []
        plugin_versions = wp_info.get("plugin_versions", {})

        # Known vulnerable plugins (subset — extend with CVE DB)
        KNOWN_VULNS = {
            "contact-form-7": {"below": "5.8.4", "cve": "CVE-2023-6449", "severity": "MEDIUM"},
            "elementor": {"below": "3.18.2", "cve": "CVE-2023-48777", "severity": "CRITICAL"},
            "wp-file-manager": {"below": "6.9", "cve": "CVE-2020-25213", "severity": "CRITICAL"},
            "all-in-one-seo-pack": {"below": "4.3.0", "cve": "CVE-2023-0585", "severity": "HIGH"},
            "duplicator": {"below": "1.5.7.1", "cve": "CVE-2023-6114", "severity": "CRITICAL"},
            "really-simple-ssl": {"below": "9.0.0", "cve": "CVE-2023-28659", "severity": "HIGH"},
            "updraftplus": {"below": "1.23.3", "cve": "CVE-2022-23981", "severity": "HIGH"},
            "wp-statistics": {"below": "14.0.1", "cve": "CVE-2023-28665", "severity": "MEDIUM"},
            "wordfence": {"below": "7.10.0", "cve": "CVE-2023-6934", "severity": "MEDIUM"},
            "woocommerce": {"below": "8.2.2", "cve": "CVE-2023-47777", "severity": "HIGH"},
        }

        for plugin, version in plugin_versions.items():
            plugin_slug = plugin.lower().strip()
            if plugin_slug in KNOWN_VULNS:
                vuln = KNOWN_VULNS[plugin_slug]
                if self._version_below(version, vuln["below"]):
                    findings.append({
                        "title": f"Vulnerable WordPress Plugin: {plugin} v{version} ({vuln['cve']})",
                        "severity": vuln["severity"],
                        "cwe": "CWE-1035",
                        "cve": vuln["cve"],
                        "description": f"Plugin '{plugin}' version {version} is below the fixed version {vuln['below']}. Known vulnerability: {vuln['cve']}",
                        "evidence_level": "E1",
                        "evidence": {
                            "plugin": plugin,
                            "detected_version": version,
                            "fixed_version": vuln["below"],
                            "cve": vuln["cve"],
                            "status": "POTENTIALLY_AFFECTED",
                        },
                    })

        return findings

    @staticmethod
    def _version_below(current: str, threshold: str) -> bool:
        """Compare semantic versions."""
        try:
            curr_parts = [int(x) for x in current.split(".")[:3]]
            thresh_parts = [int(x) for x in threshold.split(".")[:3]]
            while len(curr_parts) < 3:
                curr_parts.append(0)
            while len(thresh_parts) < 3:
                thresh_parts.append(0)
            return curr_parts < thresh_parts
        except (ValueError, AttributeError):
            return False


# Module-level convenience instance
wordpress_intelligence = WordPressIntelligence()
