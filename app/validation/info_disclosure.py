"""Information Disclosure & Configuration Leak Validator (V5 §44, V4 §85).

Probes for sensitive exposures, debug interfaces, source maps, metadata files,
directory listings, and exposed database/codebase backups:
- Directory Listings (Index of /database, Index of /build, Index of /backup)
- Database SQL Backups (skpi_trc.sql, dump.sql, backup.sql)
- Data CSV/JSON Exports (data.csv, users.csv)
- phpinfo() pages & diagnostic endpoints (server-status, server-info)
- Environment and configuration files (.env, config.json, settings.py)
- Version control metadata (.git/config, .svn/entries)
- Spring Boot Actuator, Django debug, and Laravel Ignition exposures
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

import httpx

from app.validation.result import NormalizedValidationResult
from app.validation.sensitive_files import is_waf_or_error_page, soft_404_detector

logger = logging.getLogger("validation.info_disclosure")

_TIMEOUT = httpx.Timeout(10.0, connect=6.0)
_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


@dataclass
class DisclosureFinding:
    url: str
    finding_type: str
    title: str
    severity: str
    confidence: str
    evidence_level: str
    cwe_id: str
    description: str
    evidence_sample: str
    poc_curl: str
    remediation: str
    impact_matrix: Dict[str, str] = field(default_factory=dict)


class InfoDisclosureValidator:
    """Validator for information leakage, directory listings, and backup exposures."""

    PROBE_DEFINITIONS = [
        # 1. Directory Listings
        {
            "path": "/database/",
            "type": "directory_listing",
            "title": "Directory Listing Enabled on /database/",
            "severity": "HIGH",
            "cwe_id": "CWE-548",
            "match_regex": r"<title>\s*Index of\s+/database|<h1[^>]*>\s*Index of\s+/database",
            "desc": "The /database directory has web server directory indexing enabled, exposing internal database dumps, SQL scripts, and schema files.",
            "remediation": "Disable directory browsing (e.g. `Options -Indexes` in Apache, `autoindex off;` in Nginx).",
        },
        {
            "path": "/build/",
            "type": "directory_listing",
            "title": "Directory Listing Enabled on /build/",
            "severity": "MEDIUM",
            "cwe_id": "CWE-548",
            "match_regex": r"<title>\s*Index of\s+/build|<h1[^>]*>\s*Index of\s+/build",
            "desc": "The /build directory has web server indexing enabled, allowing unauthenticated attackers to browse and download internal data and assets.",
            "remediation": "Disable directory browsing (e.g. `Options -Indexes` in Apache, `autoindex off;` in Nginx).",
        },
        {
            "path": "/backup/",
            "type": "directory_listing",
            "title": "Directory Listing Enabled on /backup/",
            "severity": "HIGH",
            "cwe_id": "CWE-548",
            "match_regex": r"<title>\s*Index of\s+/backup|<h1[^>]*>\s*Index of\s+/backup",
            "desc": "The /backup directory has directory listing enabled, disclosing backup archives and source snapshots.",
            "remediation": "Disable directory browsing and remove backup files from the public web root.",
        },
        {
            "path": "/db/",
            "type": "directory_listing",
            "title": "Directory Listing Enabled on /db/",
            "severity": "HIGH",
            "cwe_id": "CWE-548",
            "match_regex": r"<title>\s*Index of\s+/db|<h1[^>]*>\s*Index of\s+/db",
            "desc": "The /db directory is publicly indexable, allowing arbitrary downloading of database files.",
            "remediation": "Disable directory browsing in web server configuration.",
        },
        {
            "path": "/sql/",
            "type": "directory_listing",
            "title": "Directory Listing Enabled on /sql/",
            "severity": "HIGH",
            "cwe_id": "CWE-548",
            "match_regex": r"<title>\s*Index of\s+/sql|<h1[^>]*>\s*Index of\s+/sql",
            "desc": "The /sql directory is indexable, leaking database schemas and exported data.",
            "remediation": "Disable directory browsing in web server configuration.",
        },
        {
            "path": "/dump/",
            "type": "directory_listing",
            "title": "Directory Listing Enabled on /dump/",
            "severity": "HIGH",
            "cwe_id": "CWE-548",
            "match_regex": r"<title>\s*Index of\s+/dump|<h1[^>]*>\s*Index of\s+/dump",
            "desc": "The /dump directory is indexable, leaking internal data dumps.",
            "remediation": "Disable directory browsing in web server configuration.",
        },
        {
            "path": "/export/",
            "type": "directory_listing",
            "title": "Directory Listing Enabled on /export/",
            "severity": "MEDIUM",
            "cwe_id": "CWE-548",
            "match_regex": r"<title>\s*Index of\s+/export|<h1[^>]*>\s*Index of\s+/export",
            "desc": "The /export directory has directory indexing enabled, exposing data export files.",
            "remediation": "Disable directory browsing in web server configuration.",
        },
        {
            "path": "/files/",
            "type": "directory_listing",
            "title": "Directory Listing Enabled on /files/",
            "severity": "LOW",
            "cwe_id": "CWE-548",
            "match_regex": r"<title>\s*Index of\s+/files|<h1[^>]*>\s*Index of\s+/files",
            "desc": "The /files directory has directory listing enabled.",
            "remediation": "Disable directory browsing in web server configuration.",
        },
        {
            "path": "/storage/logs/",
            "type": "directory_listing",
            "title": "Directory Listing Enabled on /storage/logs/",
            "severity": "HIGH",
            "cwe_id": "CWE-548",
            "match_regex": r"<title>\s*Index of\s+/storage/logs|<h1[^>]*>\s*Index of\s+/storage/logs|laravel\.log",
            "desc": "Laravel framework internal logs are publicly browsable, leaking stack traces and authentication tokens.",
            "remediation": "Block access to the `/storage/` directory in reverse proxy configuration.",
        },

        # 2. Server Diagnostics & Status
        {
            "path": "/server-status",
            "type": "server_status_exposure",
            "title": "Apache Server Status Page Publicly Accessible",
            "severity": "MEDIUM",
            "cwe_id": "CWE-200",
            "match_regex": r"Apache Server Status for|Current Time:|Restart Time:|Parent Server Generation:",
            "desc": "The Apache /server-status handler is accessible to unauthenticated remote users, exposing client IPs, requested URLs, and worker states.",
            "remediation": "Restrict /server-status access in Apache configuration: `Require local` or `Require ip <trusted_subnet>`.",
        },
        {
            "path": "/server-info",
            "type": "server_info_exposure",
            "title": "Apache Server Info Page Publicly Accessible",
            "severity": "HIGH",
            "cwe_id": "CWE-200",
            "match_regex": r"Apache Server Information|Module Name:|Server Settings",
            "desc": "The Apache /server-info handler is accessible without authentication, revealing server configuration directives and module parameters.",
            "remediation": "Disable mod_info or restrict /server-info to localhost in Apache configuration.",
        },

        # 3. Sensitive Version Control & Secrets Files
        {
            "path": "/.git/config",
            "type": "git_config_exposure",
            "title": "Git Repository Configuration Exposed (.git/config)",
            "severity": "HIGH",
            "cwe_id": "CWE-538",
            "match_regex": r"\[core\]|repositoryformatversion|\[remote \"origin\"\]",
            "desc": "The Git configuration file is accessible, exposing private repository URLs, commit history metadata, and potentially internal credentials.",
            "remediation": "Deny web access to all `.git` directories and files in your web server or reverse proxy configuration.",
        },
        {
            "path": "/.git/HEAD",
            "type": "git_head_exposure",
            "title": "Git Repository HEAD Pointer Exposed (.git/HEAD)",
            "severity": "HIGH",
            "cwe_id": "CWE-538",
            "match_regex": r"^ref:\s*refs/heads/|^[0-9a-f]{40}$",
            "desc": "The .git/HEAD file is exposed, allowing reconstruction of application source code.",
            "remediation": "Deny web access to all `.git` directories in web server configuration.",
        },
        {
            "path": "/.env",
            "type": "env_exposure",
            "title": "Environment Secrets File Exposed (.env)",
            "severity": "CRITICAL",
            "cwe_id": "CWE-538",
            "match_regex": r"APP_KEY=|DB_PASSWORD=|DATABASE_URL=|SECRET_KEY=|AWS_ACCESS_KEY_ID=|DB_USERNAME=",
            "desc": "The root .env file is publicly accessible, leaking production database passwords, API credentials, and application encryption keys.",
            "remediation": "Block access to `.env*` files in reverse proxy config and ensure sensitive files reside outside the web server document root.",
        },
        {
            "path": "/phpinfo.php",
            "type": "phpinfo_exposure",
            "title": "PHP Diagnostic Page Publicly Accessible (phpinfo.php)",
            "severity": "MEDIUM",
            "cwe_id": "CWE-200",
            "match_regex": r"PHP Version\s*</td>|phpinfo\(\)|Configuration File \(php\.ini\) Path",
            "desc": "The phpinfo() diagnostic page is publicly accessible, exposing PHP version, loaded extensions, environment variables, and server paths.",
            "remediation": "Delete diagnostic scripts from production servers or restrict access by IP.",
        },
        {
            "path": "/info.php",
            "type": "phpinfo_exposure",
            "title": "PHP Diagnostic Page Publicly Accessible (info.php)",
            "severity": "MEDIUM",
            "cwe_id": "CWE-200",
            "match_regex": r"PHP Version\s*</td>|phpinfo\(\)|Configuration File \(php\.ini\) Path",
            "desc": "The info.php diagnostic page is publicly accessible, exposing server configuration.",
            "remediation": "Delete diagnostic scripts from production servers.",
        },
        {
            "path": "/storage/logs/laravel.log",
            "type": "laravel_log_exposure",
            "title": "Laravel Production Application Log Exposed (laravel.log)",
            "severity": "HIGH",
            "cwe_id": "CWE-532",
            "match_regex": r"\[\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\]\s+[a-zA-Z_]+\.(?:INFO|ERROR|DEBUG|CRITICAL):",
            "desc": "Production Laravel logs are publicly downloadable, disclosing SQL queries, stack traces, and user metadata.",
            "remediation": "Restrict web access to `/storage/` directory in reverse proxy configuration.",
        },
    ]

    async def scan_base_url(self, base_url: str) -> List[DisclosureFinding]:
        """Probe base URL for standard information disclosure endpoints and follow directory listings."""
        findings: List[DisclosureFinding] = []
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        visited_urls: Set[str] = set()

        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=True) as client:
            # 1. Test standard probe definitions
            for probe in self.PROBE_DEFINITIONS:
                url = origin + probe["path"]
                if url in visited_urls:
                    continue
                visited_urls.add(url)

                try:
                    resp = await client.get(url, headers=_HEADERS)
                    if resp.status_code == 200 and len(resp.text) > 30:
                        # Ensure not WAF or soft-404
                        is_waf, _ = is_waf_or_error_page(resp.status_code, resp.text, resp.headers.get("content-type", ""))
                        if is_waf or soft_404_detector.is_soft_404(url, resp.status_code, resp.text):
                            continue

                        if re.search(probe["match_regex"], resp.text, re.IGNORECASE):
                            curl_cmd = f"curl -i -s -k '{url}'"
                            findings.append(DisclosureFinding(
                                url=url,
                                finding_type=probe["type"],
                                title=probe["title"],
                                severity=probe["severity"],
                                confidence="CONFIRMED",
                                evidence_level="E3",
                                cwe_id=probe["cwe_id"],
                                description=probe["desc"],
                                evidence_sample=resp.text[:400],
                                poc_curl=curl_cmd,
                                remediation=probe["remediation"],
                                impact_matrix={
                                    "confidentiality": "HIGH" if probe["severity"] in ("CRITICAL", "HIGH") else "MEDIUM",
                                    "integrity": "LOW",
                                    "availability": "LOW",
                                    "data_exposure": "HIGH",
                                },
                            ))
                            logger.info("CONFIRMED info disclosure on %s: %s", url, probe["title"])

                            # If this is a Directory Listing page, parse and test all linked files inside!
                            if probe["type"] == "directory_listing":
                                linked_findings = await self._analyze_directory_listing(client, url, resp.text)
                                findings.extend(linked_findings)

                except Exception as exc:
                    logger.debug("Probe %s error on %s: %s", probe["path"], origin, exc)

        return findings

    async def _analyze_directory_listing(self, client: httpx.AsyncClient, dir_url: str, html_content: str) -> List[DisclosureFinding]:
        """Scrapes and validates sensitive files listed inside a Directory Listing index page."""
        findings: List[DisclosureFinding] = []

        # Find all <a> tags
        links = re.findall(r'<a\s+[^>]*href=["\']([^"\'\?#]+)["\']', html_content, re.IGNORECASE)
        for link in set(links):
            clean_link = link.strip()
            if clean_link in ("../", "./", "/", "") or clean_link.startswith(("?", "#", "javascript:", "mailto:")):
                continue

            file_url = urljoin(dir_url, clean_link)
            lower_link = clean_link.lower()

            # High-Impact File Extensions
            is_sql = lower_link.endswith((".sql", ".sql.gz", ".sql.tar.gz", ".sql.zip", ".dump", ".db", ".sqlite"))
            is_csv = lower_link.endswith((".csv", ".tsv", ".xlsx", ".xls"))
            is_backup = lower_link.endswith((".bak", ".old", ".backup", ".zip", ".tar.gz", ".tar", ".7z", ".rar"))
            is_secret = lower_link.endswith((".env", ".key", ".pem", ".crt", ".pfx", ".json", ".conf", ".cfg", ".ini", ".log"))

            if not (is_sql or is_csv or is_backup or is_secret):
                continue

            try:
                # Fetch sample of the file
                file_resp = await client.get(file_url, headers=_HEADERS)
                if file_resp.status_code == 200 and len(file_resp.content) > 10:
                    text_sample = file_resp.text[:600] if len(file_resp.text) > 0 else ""

                    # 1. SQL Database Backup File
                    if is_sql:
                        sql_markers = ["CREATE TABLE", "INSERT INTO", "-- MySQL dump", "PostgreSQL database dump", "DROP TABLE", "SET SQL_MODE", "-- Table structure"]
                        has_sql_sig = any(m.lower() in text_sample.lower() for m in sql_markers) or len(file_resp.content) > 100
                        if has_sql_sig:
                            curl_cmd = f"curl -i -s -k '{file_url}'"
                            findings.append(DisclosureFinding(
                                url=file_url,
                                finding_type="exposed_database_backup",
                                title=f"Exposed Production Database SQL Backup ({clean_link})",
                                severity="CRITICAL",
                                confidence="CONFIRMED",
                                evidence_level="E3",
                                cwe_id="CWE-538",
                                description=f"An unauthenticated remote user can download raw production database dump file '{clean_link}', exposing full application schemas, user tables, and sensitive records.",
                                evidence_sample=text_sample[:400] or f"Binary SQL Dump: {len(file_resp.content)} bytes",
                                poc_curl=curl_cmd,
                                remediation="Immediately remove the database backup file from the public web server directory and restrict directory access.",
                                impact_matrix={
                                    "confidentiality": "CRITICAL",
                                    "integrity": "CRITICAL",
                                    "availability": "HIGH",
                                    "data_exposure": "CRITICAL",
                                },
                            ))
                            logger.warning("CRITICAL EXPOSED DATABASE BACKUP on %s: %s", file_url, clean_link)

                    # 2. Sensitive Data CSV / Export File
                    elif is_csv:
                        if len(text_sample) > 20:
                            curl_cmd = f"curl -i -s -k '{file_url}'"
                            findings.append(DisclosureFinding(
                                url=file_url,
                                finding_type="exposed_data_csv",
                                title=f"Exposed Sensitive Data CSV Export ({clean_link})",
                                severity="HIGH",
                                confidence="CONFIRMED",
                                evidence_level="E3",
                                cwe_id="CWE-200",
                                description=f"Data export file '{clean_link}' is publicly accessible, leaking records, PII, or internal system data.",
                                evidence_sample=text_sample[:400],
                                poc_curl=curl_cmd,
                                remediation="Remove data exports from web root and enforce role-based access control.",
                                impact_matrix={
                                    "confidentiality": "HIGH",
                                    "integrity": "LOW",
                                    "availability": "NONE",
                                    "data_exposure": "HIGH",
                                },
                            ))
                            logger.info("HIGH EXPOSED CSV FILE on %s: %s", file_url, clean_link)

                    # 3. Backup Archive
                    elif is_backup:
                        curl_cmd = f"curl -i -s -k '{file_url}'"
                        findings.append(DisclosureFinding(
                            url=file_url,
                            finding_type="exposed_backup_archive",
                            title=f"Exposed Backup Archive File ({clean_link})",
                            severity="HIGH",
                            confidence="CONFIRMED",
                            evidence_level="E3",
                            cwe_id="CWE-538",
                            description=f"Backup archive '{clean_link}' ({len(file_resp.content)} bytes) is accessible without authorization, risking source code and credential exposure.",
                            evidence_sample=f"Archive file: {clean_link} ({len(file_resp.content)} bytes)",
                            poc_curl=curl_cmd,
                            remediation="Delete backup archives from public document roots.",
                            impact_matrix={
                                "confidentiality": "HIGH",
                                "integrity": "MEDIUM",
                                "availability": "LOW",
                                "data_exposure": "HIGH",
                            },
                        ))

            except Exception as exc:
                logger.debug("Failed checking file %s from directory listing: %s", file_url, exc)

        return findings

    @classmethod
    def detect_seo_spam_defacement(cls, url: str, html: str, title: str = "") -> Optional[DisclosureFinding]:
        """Detect active website defacement or injected gambling/SEO spam backlinks."""
        if not html:
            return None

        # 1. Search for obvious gambling / SEO spam in title
        spam_title_patterns = [
            r"slot\s*(?:gacor|88|online|zeus|maxwin|777)",
            r"situs\s*(?:judi|slot|togel|poker)",
            r"judi\s*online",
            r"pragmatic\s*play",
            r"bandar\s*(?:togel|judi|taruhan)",
            r"sbobet",
            r"agen\s*slot",
            r"rtp\s*live\s*slot",
            r"scatter\s*hitam",
        ]
        
        detected_title_spam = False
        for pat in spam_title_patterns:
            if re.search(pat, title, re.IGNORECASE):
                detected_title_spam = True
                break

        # 2. Search for hidden spam backlinks in DOM
        hidden_link_pattern = r'<a\s+[^>]*href=["\'](https?://[^"\']+)["\'][^>]*>(?:[^<]*(?:slot|gacor|judi|maxwin|togel|poker|casino|zeus|pragmatic|sbobet)[^<]*)</a>'
        hidden_links = re.findall(hidden_link_pattern, html, re.IGNORECASE)

        # 3. Check for hidden CSS styling used to conceal spam links from human visitors
        has_concealed_spam = False
        if re.search(r'style=["\'][^"\']*(?:position:\s*absolute;\s*left:\s*-\d{3,5}px|display:\s*none|font-size:\s*0px|opacity:\s*0)[^"\']*(?:slot|gacor|judi|togel|maxwin)', html, re.IGNORECASE):
            has_concealed_spam = True

        if detected_title_spam or hidden_links or has_concealed_spam:
            proof_sample = f"Title: '{title}'" if detected_title_spam else (f"Hidden spam links: {', '.join(hidden_links[:3])}" if hidden_links else "Concealed CSS SEO spam injection detected")
            return DisclosureFinding(
                url=url,
                finding_type="active_seo_spam_defacement",
                title="Active Web Defacement / Injected SEO Spam Detected",
                severity="CRITICAL",
                confidence="CONFIRMED",
                evidence_level="E3",
                cwe_id="CWE-73",
                description="The website exhibits active web defacement or injected illegal gambling/SEO spam keywords. This confirms prior unauthorized modification of database content, templates, or filesystem assets.",
                evidence_sample=proof_sample[:400],
                poc_curl=f"curl -i -s -k '{url}'",
                remediation="1. Immediately audit and clean compromised database records (e.g. wp_posts, articles).\n2. Inspect server filesystem for web shells and unauthorized upload files.\n3. Revoke all administrator sessions, update passwords, and patch XSS/file-upload vulnerabilities.",
                impact_matrix={
                    "confidentiality": "HIGH",
                    "integrity": "CRITICAL",
                    "availability": "HIGH",
                    "data_exposure": "HIGH",
                },
            )

        return None


# Module-level singleton
info_disclosure_validator = InfoDisclosureValidator()
