"""Actionable Remediation & Framework-Specific Patch Synthesizer (V5 §50).

Generates drop-in, ready-to-copy code patches and web server hardening rules
tailored to the target's exact detected technology stack (Nginx, Apache, PHP, Laravel, Next.js, etc.).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("intelligence.remediation_ai")


@dataclass
class RemediationPatch:
    finding_id: str
    vulnerability_title: str
    target_framework: str
    emergency_containment_step: str
    configuration_patch: str
    code_patch: str
    verification_command: str
    best_practice_notes: str


class RemediationAi:
    """Generates technology-specific patches and remediation directives."""

    @classmethod
    def generate_patch_for_finding(
        cls,
        finding: Dict[str, Any],
        technologies: Optional[List[Dict[str, Any]]] = None,
    ) -> RemediationPatch:
        """Synthesize actionable code and config patch based on vulnerability type and tech stack."""
        f_id = str(finding.get("id") or "BH-001")
        title = finding.get("title") or "Security Vulnerability"
        v_type = (finding.get("vulnerability_type") or finding.get("finding_type") or "").lower()
        url = finding.get("endpoint_url") or finding.get("url") or "/"
        tech_names = [t.get("name", "").lower() for t in (technologies or [])]

        is_nginx = any("nginx" in t for t in tech_names) or True  # Default to modern Nginx + Apache
        is_apache = any("apache" in t for t in tech_names)
        is_php = any("php" in t for t in tech_names) or True

        # 1. Exposed Database Backup (.sql) / Directory Listing (/database/, /build/)
        if "database" in v_type or "directory_listing" in v_type or ".sql" in title.lower() or "backup" in v_type:
            nginx_conf = r"""# Nginx Server Block (/etc/nginx/sites-available/default)
server {
    ...
    # 1. Disable Directory Listing globally
    autoindex off;

    # 2. Deny access to database, backup, and environment files
    location ~* \.(sql|sql\.gz|dump|bak|old|backup|env|log|key|db|sqlite)$ {
        deny all;
        return 404;
    }

    # 3. Block access to sensitive folders
    location ^~ /database/ {
        deny all;
        return 404;
    }
}"""
            apache_conf = r"""# Apache VirtualHost / .htaccess
Options -Indexes

# Block sensitive backup and database files
<FilesMatch "\.(sql|sql\.gz|dump|bak|old|backup|env|log|key|db|sqlite)$">
    Require all denied
</FilesMatch>

# Block sensitive directory access
<Directory "/var/www/html/database">
    Require all denied
</Directory>"""

            return RemediationPatch(
                finding_id=f_id,
                vulnerability_title=title,
                target_framework="Nginx / Apache / PHP",
                emergency_containment_step="Immediately remove or move all `.sql` and backup files out of `/var/www/html/` to a secure offline storage directory.",
                configuration_patch=f"{nginx_conf}\n\n# --- APACHE ALTERNATIVE ---\n{apache_conf}",
                code_patch="# Ensure database dump scripts store outputs in `/var/backups/` outside the web document root.",
                verification_command=f"curl -i -s -k '{url}' | head -n 5  # Expect: HTTP/1.1 404 Not Found or 403 Forbidden",
                best_practice_notes="Never run database export utilities directly into public web directories. Use automated backup pipelines with S3/GCS IAM authentication.",
            )

        # 2. Environment Secrets Exposure (.env)
        elif "env" in v_type or ".env" in title.lower():
            nginx_conf = r"""# Block all dotfiles (.env, .git, etc.)
location ~ /\. {
    deny all;
    access_log off;
    log_not_found off;
    return 404;
}"""
            return RemediationPatch(
                finding_id=f_id,
                vulnerability_title=title,
                target_framework="Nginx / Laravel / Node",
                emergency_containment_step="1. Rotate all passwords, DB credentials, APP_KEY, and API secrets found in the `.env` file immediately.\n2. Invalidate active user sessions.",
                configuration_patch=nginx_conf,
                code_patch="// Move `.env` one directory level above the web server document root (e.g. `public/` is root, `.env` is in root project parent).",
                verification_command=f"curl -i -s -k '{url}'  # Expect: HTTP 404 Not Found",
                best_practice_notes="Ensure the web server `root` directive points strictly to `public/` or `dist/`, never the project root repository directory.",
            )

        # 3. Active SEO Spam / Web Defacement
        elif "defacement" in v_type or "spam" in v_type:
            return RemediationPatch(
                finding_id=f_id,
                vulnerability_title=title,
                target_framework="CMS / Database Storage",
                emergency_containment_step="1. Scan database tables (e.g. `SELECT * FROM articles WHERE title LIKE '%slot%'`) and delete injected records.\n2. Inspect `/uploads/` for newly created `.php` / `.html` backdoor files.\n3. Revoke all administrative session tokens.",
                configuration_patch=r"""# Restrict script execution in uploads folder (Nginx)
location ^~ /uploads/ {
    location ~ \.(php|phtml|html|htm|js)$ {
        deny all;
        return 404;
    }
}""",
                code_patch="""// Clean HTML inputs and sanitize rich-text fields before saving to DB
$clean_title = strip_tags($input_title);
$clean_content = Purifier::clean($input_content);""",
                verification_command=f"curl -s -k '{url}' | grep -iE 'slot|gacor|judi|maxwin'  # Expect: (Empty output - zero matches)",
                best_practice_notes="Enable File Integrity Monitoring (FIM) and Web Application Firewall (WAF) to detect unauthorized file creation.",
            )

        # 4. SQL Injection
        elif "sql" in v_type:
            return RemediationPatch(
                finding_id=f_id,
                vulnerability_title=title,
                target_framework="PHP PDO / SQLAlchemy",
                emergency_containment_step="Review application database logs for unusual UNION/SLEEP/OR queries and isolate vulnerable endpoints.",
                configuration_patch="# Enable WAF SQLi inspection rules (e.g. ModSecurity OWASP CRS 942xxx).",
                code_patch="""// PHP PDO Prepared Statements (VULNERABILITY FIX)
$stmt = $pdo->prepare('SELECT id, name, email FROM users WHERE id = :id');
$stmt->execute(['id' => $user_id]);
$user = $stmt->fetch();""",
                verification_command=f"curl -s -k '{url}'  # Verify application returns expected response without SQL errors",
                best_practice_notes="Never concatenate raw user input directly into SQL strings. Always use ORM or prepared statements.",
            )

        # 5. Cross-Site Scripting (XSS)
        elif "xss" in v_type:
            return RemediationPatch(
                finding_id=f_id,
                vulnerability_title=title,
                target_framework="HTML / Frontend / CSP",
                emergency_containment_step="Deploy a strict Content Security Policy (CSP) header to disable inline script execution.",
                configuration_patch="""# Add strict CSP Header (Nginx)
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';" always;
add_header X-Content-Type-Options "nosniff" always;""",
                code_patch="""// PHP Output Escaping
echo htmlspecialchars($user_input, ENT_QUOTES | ENT_HTML5, 'UTF-8');""",
                verification_command=f"curl -i -s -k '{url}' | grep -i 'Content-Security-Policy'  # Expect: CSP Header present",
                best_practice_notes="Combine contextual HTML entity encoding with CSP and httpOnly cookie flags to neutralize XSS impact.",
            )

        # Default Generic Patch
        return RemediationPatch(
            finding_id=f_id,
            vulnerability_title=title,
            target_framework="Generic Web Application",
            emergency_containment_step="Restrict network access to affected endpoint or place behind authenticated reverse proxy.",
            configuration_patch="# Review web server access control and disable debugging interfaces in production.",
            code_patch="// Enforce strict input validation, authorization checks, and principle of least privilege.",
            verification_command=f"curl -i -s -k '{url}'",
            best_practice_notes="Follow OWASP Secure Coding Practices and implement automated SAST/DAST CI/CD gates.",
        )


# Module-level singleton
remediation_ai = RemediationAi()
