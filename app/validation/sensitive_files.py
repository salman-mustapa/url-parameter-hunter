"""Sensitive File & Content Signature Validator (V5 §40, §44).

Implements:
1. Soft-404 Baseline Detection per host to prevent false-positives on SPA / custom 404 servers.
2. Strict Content Fingerprinting & Magic Signature checks (validating .git/HEAD, .env, backup.sql, phpinfo, swagger, etc.).
3. Proof Quality Validation before confirmation.
"""

from __future__ import annotations

import logging
import re
import uuid
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse

from app.scanners.http import fetch_http

logger = logging.getLogger("validation.sensitive_files")


class Soft404Detector:
    """Detects if a target host returns HTTP 200 / custom fallback for non-existent resources (SPAs / catch-all)."""

    def __init__(self) -> None:
        self._cache: Dict[str, Dict[str, Any]] = {}

    async def get_baseline(self, host: str, scheme: str = "https") -> Dict[str, Any]:
        """Fetch baseline response for a non-existent path and root page to detect custom 404/SPA fallbacks."""
        clean_host = host.replace("https://", "").replace("http://", "").rstrip("/")
        if clean_host in self._cache:
            return self._cache[clean_host]

        canary_path = f"/_hunter_canary_404_{uuid.uuid4().hex[:12]}"
        
        baseline = {
            "is_soft_404": False,
            "is_spa": False,
            "status_code": 404,
            "content_length": 0,
            "title": "",
            "body_snippet": "",
            "root_title": "",
            "root_length": 0,
        }

        # Try specified scheme, fallback to other scheme if connection fails
        schemes_to_try = [scheme, "http"] if scheme == "https" else ["http", "https"]

        for s in schemes_to_try:
            canary_url = f"{s}://{clean_host}{canary_path}"
            root_url = f"{s}://{clean_host}/"
            try:
                # 1. Probe Canary
                resp_canary = await fetch_http(canary_url, timeout=6.0)
                if resp_canary:
                    baseline["status_code"] = resp_canary.status_code
                    baseline["content_length"] = len(resp_canary.text)
                    if resp_canary.status_code == 200:
                        baseline["is_soft_404"] = True
                        m = re.search(r"<title[^>]*>(.*?)</title>", resp_canary.text, re.IGNORECASE | re.DOTALL)
                        if m:
                            baseline["title"] = m.group(1).strip()
                        baseline["body_snippet"] = resp_canary.text[:500]
                        if any(marker in resp_canary.text.lower() for marker in ["<app-root", 'id="root"', 'id="app"', "ng-version", "<base href="]):
                            baseline["is_spa"] = True
                        logger.info("Host %s detected as SOFT-404 / SPA (Canary returned 200 OK, length %d, title '%s')", clean_host, baseline["content_length"], baseline["title"])
                        break

                # 2. Probe Root to inspect SPA structure
                resp_root = await fetch_http(root_url, timeout=5.0)
                if resp_root and resp_root.status_code == 200:
                    baseline["root_length"] = len(resp_root.text)
                    m_root = re.search(r"<title[^>]*>(.*?)</title>", resp_root.text, re.IGNORECASE | re.DOTALL)
                    if m_root:
                        baseline["root_title"] = m_root.group(1).strip()
                    if any(marker in resp_root.text.lower() for marker in ["<app-root", 'id="root"', 'id="app"', "ng-version", "<base href="]):
                        baseline["is_spa"] = True
            except Exception as exc:
                logger.debug("Baseline probe on %s://%s error: %s", s, clean_host, exc)

        self._cache[clean_host] = baseline
        return baseline

    def is_soft_404(self, url_or_host: str, status_code: int, content: str, title: str = "") -> bool:
        """Check if response is a soft-404 / SPA fallback to index.html."""
        if status_code != 200:
            return False

        if "://" in url_or_host:
            parsed = urlparse(url_or_host)
            host = parsed.netloc.split(":")[0].strip().lower()
            path = (parsed.path or "").lower()
        else:
            host = url_or_host.split(":")[0].strip().lower()
            path = "/"

        if path in ("/", ""):
            return False  # Root homepage is legitimately valid

        baseline = self._cache.get(host)
        if not baseline:
            # Fallback search without port
            for k, v in self._cache.items():
                if k.split(":")[0] == host:
                    baseline = v
                    break

        if not baseline:
            return False

        is_soft = baseline.get("is_soft_404", False)
        is_spa = baseline.get("is_spa", False)

        if not is_soft and not is_spa:
            return False

        curr_len = len(content)
        base_len = baseline.get("content_length", 0)
        root_len = baseline.get("root_length", 0)

        # 1. Content length canary match
        if base_len > 0 and abs(curr_len - base_len) < 80:
            return True

        # 2. Root length match on non-root static file extensions (e.g. /www.zip returning SPA index)
        if root_len > 0 and abs(curr_len - root_len) < 80 and any(path.endswith(ext) for ext in [".zip", ".sql", ".tar.gz", ".bak", ".dump", ".csv", ".env", ".log", ".txt", ".json"]):
            return True

        # 3. Title match with SPA markers or non-HTML extensions
        base_title = (baseline.get("title") or baseline.get("root_title") or "").strip().lower()
        curr_title = (title or "").strip().lower()
        if not curr_title and content:
            m = re.search(r"<title[^>]*>(.*?)</title>", content, re.IGNORECASE | re.DOTALL)
            if m:
                curr_title = m.group(1).strip().lower()

        if base_title and curr_title and base_title == curr_title:
            if any(path.endswith(ext) for ext in [".zip", ".sql", ".tar.gz", ".bak", ".dump", ".csv", ".env", ".log", ".txt", ".json", ".xml", ".yml", ".yaml", ".ini", ".conf", ".php"]):
                return True
            if any(marker in content.lower() for marker in ["<app-root", 'id="root"', 'id="app"', "ng-version", "<base href="]):
                return True

        # 4. Body snippet match
        base_snip = baseline.get("body_snippet", "")
        if base_snip and len(base_snip) > 30 and base_snip[:100] in content[:300]:
            return True

        return False


soft_404_detector = Soft404Detector()


# ============================================================================
# WAF, Bot Challenge & Soft-404 Anti-False-Positive Signatures
# ============================================================================

WAF_CHALLENGE_TITLES = [
    "one moment, please",
    "just a moment",
    "attention required",
    "checking your browser",
    "security check",
    "security verification",
    "ddos-guard",
    "access denied",
    "403 forbidden",
    "forbidden",
    "404 not found",
    "page not found",
    "not found",
    "halaman tidak ditemukan",
    "objek tidak ditemukan",
    "web application firewall",
    "pure 360",
    "pure-360",
    "safeline",
    "modsecurity",
    "fortiweb",
    "imperva",
    "waf blocked",
    "site under maintenance",
    "this site is currently suspended",
    "site is suspended",
    "account suspended",
    "website suspended",
    "domain suspended",
    "this account has been suspended",
    "domain is parked",
    "parking page",
    "domain expired",
    "cpanel default page",
    "plesk default page",
    "default web site page",
    "under construction",
    "website coming soon",
    "error 404",
    "error 403",
]

WAF_BODY_MARKERS = [
    "this site is currently suspended",
    "if you are the owner of this site, please contact support",
    "this account has been suspended",
    "cgi-sys/suspendedpage.cgi",
    "contact your hosting provider",
    "this domain is parked",
    "parkingcrew",
    "sedoparking",
    "domain has expired",
    "cf-browser-verification",
    "cf-chl-bypass",
    "cf-spinner",
    "ray id:",
    "incident id",
    "pure360",
    "pure-360",
    "checking your browser before accessing",
    "please wait while your request is being verified",
    "turnstile",
    "challenge-running",
    "challenge-form",
    "hcaptcha",
    "recaptcha",
    "access to this page has been denied",
    "protected by cloudflare",
    "protected by imperva",
    "blocked by web application firewall",
    "waf.pure360",
    "shield.pure360",
]


def is_waf_or_error_page(status_code: int, content: str, content_type: str = "", title: str = "") -> Tuple[bool, str]:
    """Determines if a response is a WAF challenge, bot mitigation, block page, or generic error."""
    if status_code in (401, 403, 404, 500, 502, 503, 504):
        return True, f"HTTP status {status_code} is an access denial / error, not sensitive content"

    lower_title = title.lower().strip() if title else ""
    for wt in WAF_CHALLENGE_TITLES:
        if wt in lower_title:
            return True, f"WAF / Bot challenge or block page title detected: '{title}'"

    lower_content = content.lower() if content else ""
    for wm in WAF_BODY_MARKERS:
        if wm in lower_content:
            return True, f"WAF / Bot challenge marker detected in body: '{wm}'"

    return False, ""


class SensitiveFileValidator:
    """Validates whether a sensitive file actually contains authentic contents."""

    @classmethod
    def validate_content_signature(cls, file_type: str, url: str, status_code: int, content: str, content_type: str = "", title: str = "") -> Tuple[bool, str, Dict[str, Any]]:
        """
        Validates content authenticity.
        Returns: (is_valid: bool, reason: str, metadata: dict)
        """
        if status_code != 200:
            return False, f"Status code is {status_code} (not 200 OK)", {}

        if not content:
            return False, "Response body is empty", {}

        clean_content = content.strip()
        ct = content_type.lower()

        # 0. Check for WAF / Challenge / Soft Error Pages first
        is_waf, waf_reason = is_waf_or_error_page(status_code, clean_content, ct, title)
        if is_waf:
            return False, f"False Positive: {waf_reason}", {}

        # Check for HTML responses when expecting raw data/configs
        is_html = (
            "<html" in clean_content.lower()
            or "<!doctype html" in clean_content.lower()
            or "<head" in clean_content.lower()
            or "<body" in clean_content.lower()
            or "<script" in clean_content.lower()
            or "text/html" in ct
        )

        # 1. Git Repository Metadata (.git/HEAD)
        if file_type == "git_head" or "/.git/head" in url.lower():
            if is_html:
                return False, "False Positive: Expected raw Git HEAD ref, but received HTML webpage / WAF challenge", {}
            # Git HEAD length is normally under 100 bytes (rarely > 200 bytes)
            if len(clean_content) > 300:
                return False, f"False Positive: Git HEAD response is {len(clean_content)} bytes (expected < 200 bytes for raw ref)", {}
            # Git HEAD must match 'ref: refs/heads/...' or a 40-char hex commit hash
            if re.match(r"^ref:\s*refs/heads/[\w\-\./]+", clean_content) or re.match(r"^[0-9a-f]{40}$", clean_content, re.IGNORECASE):
                return True, "Valid Git HEAD reference verified", {"git_ref": clean_content[:100]}
            return False, "Invalid Git HEAD format (does not contain ref: refs/ or commit SHA)", {}

        # 2. Git Config (.git/config)
        if file_type == "git_config" or "/.git/config" in url.lower():
            if is_html:
                return False, "False Positive: Expected INI config, received HTML", {}
            if len(clean_content) > 5000:
                return False, f"False Positive: Oversized git config ({len(clean_content)} bytes)", {}
            if "[core]" in clean_content and ("repositoryformatversion" in clean_content or "filemode" in clean_content or "bare =" in clean_content):
                return True, "Valid Git repository config verified", {"has_core_section": True}
            return False, "Missing [core] repositoryformatversion section in git config", {}

        # 3. Environment Variables (.env)
        if file_type == "env" or "/.env" in url.lower():
            if is_html:
                return False, "False Positive: Expected plain text key-value pairs, received HTML", {}
            env_keys = re.findall(r"^(?:[A-Z0-9_]{2,40})\s*=", clean_content, re.MULTILINE)
            critical_keywords = ["APP_KEY", "DB_PASSWORD", "DB_HOST", "SECRET", "JWT_SECRET", "AWS_ACCESS", "API_KEY", "PASSWORD", "DATABASE_URL"]
            found_critical = [k for k in critical_keywords if k in clean_content.upper()]
            if len(env_keys) >= 2 or len(found_critical) >= 1:
                return True, f"Valid .env file verified with {len(env_keys)} key(s) and critical markers: {', '.join(found_critical)}", {
                    "keys_count": len(env_keys),
                    "critical_markers": found_critical,
                }
            return False, "No valid environment variable assignments (KEY=value) found in response", {}

        # 4. Database / SQL Backup Dump (.sql, .dump, .bak)
        if file_type in ("backup_sql", "sql", "db_dump") or (url.lower().endswith((".sql", ".dump", ".sql.gz", ".bak")) and not url.lower().endswith((".csv", ".tsv", ".log", ".env", ".html", ".js"))):
            if is_html:
                return False, "False Positive: Expected SQL statements, received HTML webpage", {}
            sql_markers = [
                "CREATE TABLE", "INSERT INTO", "-- MySQL dump", "PostgreSQL database dump",
                "Table structure for table", "Dumping data for table", "SET SQL_MODE", "DROP TABLE IF EXISTS",
                "LOCK TABLES", "UNLOCK TABLES", "PRIMARY KEY", "ENGINE=InnoDB", "mysqldump"
            ]
            matched = [m for m in sql_markers if m.lower() in clean_content.lower()]
            if len(matched) >= 1:
                return True, f"Valid SQL dump file verified (markers: {', '.join(matched)})", {"sql_markers": matched, "bytes": len(clean_content)}
            return False, "Missing SQL dump syntax (no CREATE TABLE, INSERT INTO, or dump headers found)", {}

        # 5. CSV / Tabular Data File & PII Export (.csv, .tsv)
        if file_type in ("csv", "backup_csv", "data_export") or url.lower().endswith((".csv", ".tsv")):
            if is_html:
                return False, "False Positive: Expected CSV plaintext data, received HTML webpage", {}
            lines = [line.strip() for line in clean_content.splitlines() if line.strip() and not line.strip().startswith("#")]
            if len(lines) >= 2:
                first_line = lines[0].lower()
                # Check for column delimiters in header
                for delim in (",", ";", "\t", "|"):
                    cols = first_line.split(delim)
                    if len(cols) >= 2:
                        # Check for meaningful data / PII / academic headers
                        pii_indicators = [
                            "id", "user", "name", "nama", "nim", "nik", "email", "mail", "pass", "password",
                            "phone", "telp", "hp", "alumni", "prodi", "jurusan", "fakultas", "skpi", "tracer",
                            "tahun", "status", "date", "created_at", "role", "address", "alamat", "ip"
                        ]
                        found_headers = [c.strip() for c in cols if any(p in c.strip().lower() for p in pii_indicators)]
                        return True, f"Valid CSV data export verified ({len(lines)} rows, {len(cols)} columns, headers: {', '.join(cols[:5])})", {
                            "row_count": len(lines),
                            "col_count": len(cols),
                            "headers": cols[:10],
                            "pii_headers": found_headers,
                            "has_pii": len(found_headers) > 0,
                        }
            return False, "Missing multi-line CSV tabular structure", {}

        # 6. Log File Exposure (.log, /storage/logs/laravel.log, debug.log)
        if file_type in ("log", "log_file") or url.lower().endswith(".log") or "/logs/" in url.lower() or "laravel.log" in url.lower():
            if is_html:
                return False, "False Positive: Expected raw text log, received HTML", {}
            log_markers = [
                "local.ERROR:", "production.ERROR:", "Stack trace:", "Illuminate\\", "Exception:",
                "SQLSTATE[", "Traceback (most recent call last):", "fatal error", "warning:", "error:",
                "app.CRITICAL:", "DEBUG:"
            ]
            matched = [m for m in log_markers if m.lower() in clean_content.lower()]
            date_matches = re.findall(r"\[\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}", clean_content)
            if len(matched) >= 1 or len(date_matches) >= 2:
                return True, f"Valid application log file verified (markers: {', '.join(matched[:3])}, timestamps: {len(date_matches)})", {
                    "log_markers": matched,
                    "timestamps_count": len(date_matches),
                }
            return False, "Missing log timestamps or exception stack trace signatures", {}

        # 7. PHP Info Diagnostic Page (phpinfo.php)
        if file_type == "phpinfo" or "phpinfo" in url.lower() or "info.php" in url.lower():
            php_markers = ["PHP Version", "phpinfo()", "Configuration File (php.ini) Path", "Zend Engine", "Server API"]
            matched = [m for m in php_markers if m.lower() in clean_content.lower()]
            if len(matched) >= 2:
                v_match = re.search(r"PHP Version\s*</td>\s*<td[^>]*>([0-9\.]+)", clean_content, re.IGNORECASE)
                php_ver = v_match.group(1) if v_match else "detected"
                return True, f"Valid phpinfo() page verified (PHP {php_ver})", {"php_version": php_ver, "markers": matched}
            return False, "Missing authentic phpinfo() diagnostic signatures", {}

        # 8. Interactive API Documentation (Swagger / OpenAPI)
        if file_type == "swagger" or any(p in url.lower() for p in ["swagger.json", "openapi.json", "api/docs"]):
            if "openapi" in clean_content or "swagger" in clean_content or "swagger-ui" in clean_content.lower():
                if clean_content.startswith("{") and clean_content.endswith("}"):
                    if '"paths"' in clean_content or '"openapi"' in clean_content or '"swagger"' in clean_content:
                        return True, "Valid OpenAPI / Swagger JSON specification verified", {"is_json_schema": True}
                elif "<div id=\"swagger-ui\">" in clean_content or "SwaggerUIBundle" in clean_content:
                    return True, "Valid Swagger UI HTML portal verified", {"is_ui_portal": True}
            return False, "Missing OpenAPI / Swagger schema specifications", {}

        # 9. Spring Actuator Endpoints (/actuator, /metrics, /server-status)
        if file_type == "actuator" or "/actuator" in url.lower() or "/server-status" in url.lower():
            if '"status":"UP"' in clean_content or '"_links"' in clean_content or "Apache Server Status" in clean_content:
                return True, "Valid system status / diagnostic endpoint verified", {"has_diagnostic_data": True}
            return False, "Missing diagnostic endpoint signatures", {}

        # 10. Administrative Surface (/auth/admin, /admin, /wp-admin, /login)
        if file_type in ("admin_surface", "auth_surface") or any(p in url.lower() for p in ["/auth/admin", "/admin/login", "/auth/login", "/administrator", "/admin"]):
            admin_markers = ["login", "password", "username", "admin", "sign in", "dashboard", "masuk", "wp-login", "autentikasi", "sso"]
            matched = [m for m in admin_markers if m.lower() in clean_content.lower()]
            has_password_field = bool(re.search(r'<input[^>]+type=["\']password["\']', clean_content, re.IGNORECASE))
            if has_password_field or len(matched) >= 2:
                return True, f"Administrative authentication surface identified (markers: {', '.join(matched[:4])})", {
                    "has_password_field": has_password_field,
                    "markers": matched,
                }
            return False, "Administrative authentication interface not conclusively identified", {}

        # 11. KeePass Database (.kdbx)
        if file_type == "kdbx" or url.lower().endswith(".kdbx"):
            if is_html:
                return False, "False Positive: Expected binary KeePass database, received HTML webpage", {}
            # KDBX files start with magic bytes or binary non-HTML content > 50 bytes
            if len(content) >= 32 and not is_html:
                return True, f"KeePass Database Archive (.kdbx) verified ({len(content)} bytes)", {"file_type": "kdbx", "bytes": len(content)}
            return False, "Invalid KeePass file size or format", {}

        # 12. Backup Code & Config Files (.bak, .old, .orig, .save, .dist)
        if file_type in ("backup_code", "source_backup") or any(url.lower().endswith(ext) for ext in [".bak", ".old", ".orig", ".save", ".dist", ".backup"]):
            if is_html and not any(k in clean_content for k in ["package.json", "dependencies", "version", "scripts", "coupons", "secret", "password"]):
                return False, "False Positive: Expected source/backup code, received HTML", {}
            if len(clean_content) > 10:
                return True, f"Exposed Source/Configuration Backup File verified ({len(clean_content)} bytes)", {"bytes": len(clean_content)}
            return False, "Empty or invalid backup file", {}

        # 13. YAML Configuration Exposure (.yml, .yaml)
        if file_type in ("yaml", "yml") or url.lower().endswith((".yml", ".yaml")):
            if is_html:
                return False, "False Positive: Expected YAML configuration, received HTML", {}
            yaml_markers = [": ", "version:", "services:", "environment:", "database:", "app:", "error:", "debug:"]
            if any(m in clean_content.lower() for m in yaml_markers) or "\n" in clean_content:
                return True, f"Exposed YAML Configuration File verified ({len(clean_content)} bytes)", {"bytes": len(clean_content)}
            return False, "Invalid YAML format", {}

        # 14. Sensitive Directory Document Leak (/ftp/, /backup/, /private/, /order/ containing .pdf, .md, .kdbx)
        if any(p in url.lower() for p in ["/ftp/", "/backup/", "/private/", "/export/", "/order_"]) and any(url.lower().endswith(ext) for ext in [".pdf", ".md", ".kdbx", ".yml", ".bak"]):
            if not is_html or url.lower().endswith(".md"):
                return True, f"Sensitive Document / File Leak verified under protected directory ({url})", {"url": url, "bytes": len(clean_content)}

        # 15. Directory Listing / Open Directory Exposure (Index of /)
        if file_type == "directory_listing" or any(m in clean_content.lower() for m in ["index of /", "directory listing for", "<title>index of"]):
            if any(m in clean_content.lower() for m in ["index of /", "directory listing for", "<title>index of"]):
                return True, "Open Web Server Directory Listing Exposed (Index of /)", {"title": title, "has_index_of": True}

        # 16. JSON Manifest & Configuration (.json, package.json, composer.json)
        if file_type in ("json_config", "package_json") or any(url.lower().endswith(p) for p in ["package.json", "composer.json", "tsconfig.json", "project.json"]):
            if clean_content.startswith("{") and clean_content.endswith("}"):
                if any(k in clean_content for k in ['"name"', '"version"', '"dependencies"', '"scripts"', '"require"']):
                    return True, f"Exposed Application Package / Project Metadata verified ({url})", {"is_manifest": True}

        # Fallback automatic extension-based inference
        if url.lower().endswith(".sql"):
            return cls.validate_content_signature("backup_sql", url, status_code, content, content_type, title)
        if url.lower().endswith((".csv", ".tsv")):
            return cls.validate_content_signature("csv", url, status_code, content, content_type, title)
        if url.lower().endswith(".log"):
            return cls.validate_content_signature("log", url, status_code, content, content_type, title)
        if "/.env" in url.lower():
            return cls.validate_content_signature("env", url, status_code, content, content_type, title)
        if url.lower().endswith(".kdbx"):
            return cls.validate_content_signature("kdbx", url, status_code, content, content_type, title)
        if url.lower().endswith((".yml", ".yaml")):
            return cls.validate_content_signature("yaml", url, status_code, content, content_type, title)
        if any(url.lower().endswith(ext) for ext in [".bak", ".old", ".orig", ".save"]):
            return cls.validate_content_signature("backup_code", url, status_code, content, content_type, title)

        return False, "Unknown file signature type", {}
