"""Dynamic Multi-Stage Web Crawler & Endpoint Discovery Engine (V5 §13, §68).

Key Features:
1. Soft-404 Baseline Detection per host to prevent false-positives on SPA / catch-all routers.
2. Passive URL Harvester (AlienVault OTX & Archive.org Wayback CDX).
3. Recursive Dynamic Web Crawler with configurable depth and link canonicalization.
4. JavaScript Endpoint & Route Scraper (extracting REST, GraphQL, and Axios/Fetch routes from JS bundles).
5. Recursive Sitemap.xml & Robots.txt Parser.
6. Dynamic Technology-Aware Path Discovery.
7. Heuristic Parameter Mining integration.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.tools.dirsearch_adapter import DirsearchAdapter
from app.adapters.tools.katana_adapter import KatanaAdapter
from app.core.config import settings
from app.core.db import AsyncSessionLocal
from app.core.resource_guard import resource_guard
from app.core.sanitizer import sanitize_text
from app.models.models import Asset, Parameter, Technology, URL
from app.scanners.base import ScanContext
from app.scanners.http import extract_title, fetch_http
from app.scanners.parameter_miner import mine_parameters_for_url
from app.validation.sensitive_files import SensitiveFileValidator, is_waf_or_error_page, soft_404_detector

logger = logging.getLogger("scanner.web")

# Dynamic discovery seeds based on recognized frameworks/tech
FRAMEWORK_DISCOVERY_MAP = {
    "wordpress": [
        "/wp-json/",
        "/wp-json/wp/v2/posts",
        "/wp-json/wp/v2/users",
        "/wp-login.php",
        "/xmlrpc.php",
        "/wp-content/plugins/",
    ],
    "laravel": [
        "/api",
        "/telescope",
        "/horizon",
        "/_ignition/health-check",
        "/sanctum/csrf-cookie",
    ],
    "spring": [
        "/actuator",
        "/actuator/health",
        "/actuator/env",
        "/actuator/metrics",
        "/actuator/mappings",
    ],
    "django": [
        "/admin/login/",
        "/api/schema/",
        "/static/",
    ],
    "drupal": [
        "/user/login",
        "/core/install.php",
    ],
}

# Targeted High-Value Seed Endpoints for FFUF/Katana-Grade Web Discovery (V10 Engine)
TARGETED_SEED_PATHS = [
    # 1. Metadata & Open Standards Discovery
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association",

    # 2. Database Backups, SQL Dumps & Archives (CWE-200 / T1552 / T1530)
    "/database/",
    "/database/backup.sql",
    "/database/db.sql",
    "/database/dump.sql",
    "/database/data.sql",
    "/database/database.sql",
    "/database/users.sql",
    "/database/schema.sql",
    "/database/export.sql",
    "/database/data.csv",
    "/database/export.csv",
    "/backup/",
    "/backup.sql",
    "/backup.zip",
    "/backup.tar.gz",
    "/backup.bak",
    "/backup.dump",
    "/backups/",
    "/backups/db.sql",
    "/backups/backup.sql",
    "/db/",
    "/db.sql",
    "/db.dump",
    "/sql/",
    "/sql/backup.sql",
    "/sql/dump.sql",
    "/dump/",
    "/dump.sql",
    "/db_backup.sql",
    "/dump_db.sql",
    "/site_backup.zip",
    "/www.zip",
    "/backup_db.tar.gz",
    "/backup_site.tar.gz",

    # 3. Sensitive Configuration Files & Secrets (CWE-798 / T1552.001)
    "/.env",
    "/.env.local",
    "/.env.prod",
    "/.env.production",
    "/.env.development",
    "/.env.stage",
    "/.env.staging",
    "/.env.backup",
    "/.env.save",
    "/.env.old",
    "/.env.sample",
    "/.env.example",
    "/config.php.bak",
    "/configuration.php.bak",
    "/wp-config.php.bak",
    "/database.php.bak",
    "/settings.py.bak",
    "/web.config",
    "/.htaccess",
    "/.htpasswd",

    # 4. Source Code Repositories & Build Artifacts (CWE-538 / T1596.005)
    "/.git/HEAD",
    "/.git/config",
    "/.git/index",
    "/.git/logs/HEAD",
    "/.svn/entries",
    "/.svn/all-wcprops",
    "/.hg/dirstate",
    "/.bzr/README",
    "/.vscode/settings.json",
    "/.idea/workspace.xml",
    "/package.json",
    "/composer.json",
    "/composer.lock",
    "/package-lock.json",
    "/Dockerfile",
    "/docker-compose.yml",
    "/docker-compose.yaml",

    # 5. Diagnostic, Profiler & Framework Endpoints (CWE-200 / T1592)
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/php_info.php",
    "/server-status",
    "/server-info",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/mappings",
    "/actuator/metrics",
    "/actuator/heapdump",
    "/actuator/prometheus",
    "/actuator/beans",
    "/actuator/configprops",
    "/actuator/loggers",
    "/telescope",
    "/telescope/requests",
    "/horizon",
    "/_ignition/health-check",
    "/_ignition/execute-solution",
    "/debugbar/",
    "/elmah.axd",
    "/trace.axd",
    "/__clockwork/",
    "/debug/vars",
    "/metrics",
    "/prometheus",

    # 6. API Documentation, Schemas & GraphQL (CWE-200 / T1595)
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/swagger",
    "/swagger/index.html",
    "/swagger-ui.html",
    "/swagger-ui/index.html",
    "/swagger.json",
    "/swagger.yaml",
    "/api/swagger.json",
    "/api-docs",
    "/api/docs",
    "/docs",
    "/api/documentation",
    "/openapi.json",
    "/openapi.yaml",
    "/api/openapi.json",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/graphql",
    "/graphiql",
    "/api/graphql",
    "/altair",
    "/playground",

    # 7. Tabular PII Data & Exports (CWE-359 / T1005)
    "/data.csv",
    "/export.csv",
    "/users.csv",
    "/alumni.csv",
    "/skpi.csv",
    "/students.csv",
    "/customers.csv",
    "/orders.csv",
    "/members.csv",
    "/database/data.csv",
    "/database/export.csv",
    "/export/alumni.csv",
    "/export/users.csv",
    "/exports/data.csv",
    "/files/export.csv",
    "/data/users.csv",
    "/backup.csv",
    "/report.csv",
    "/tracer.csv",

    # 8. Server & Application Log Files (CWE-532 / T1082)
    "/storage/logs/laravel.log",
    "/logs/debug.log",
    "/logs/error.log",
    "/logs/access.log",
    "/logs/app.log",
    "/logs/application.log",
    "/logs/system.log",
    "/debug.log",
    "/error.log",
    "/access.log",
    "/app.log",
    "/system.log",
    "/npm-debug.log",
    "/yarn-error.log",
    "/log/",
    "/logs/",

    # 9. Discovery & Search Endpoints
    "/search",
    "/search/",
    "/find",
    "/query",

    # 10. Modern REST API, SPA & Pentest Sandbox Endpoints (OWASP Juice Shop / REST APIs)
    "/rest/products/search?q=",
    "/rest/products/search",
    "/rest/user/login",
    "/rest/user/change-password",
    "/rest/user/whoami",
    "/rest/basket/1",
    "/rest/basket/2",
    "/rest/captcha/",
    "/rest/saveLoginIp",
    "/rest/track-order/",
    "/rest/admin/application-version",
    "/rest/admin/application-configuration",
    "/api/Users",
    "/api/Users/1",
    "/api/Feedbacks",
    "/api/Challenges",
    "/api/Products",
    "/api/BasketItems",
    "/api/Cards",
    "/api/Addresss",
    "/ftp/",
    "/ftp/legal.md",
    "/ftp/incident-support.kdbx",
    "/ftp/package.json.bak",
    "/ftp/suspicious_errors.yml",
    "/ftp/eastere.gg",
    "/ftp/coupons_2013.md.bak",
    "/support/logs",
    "/support/logs/access.log",
]


def _extract_parameters_from_url(url_str: str) -> list[tuple[str, str]]:
    """Extracts (param_name, location) from URL query strings."""
    parsed = urlparse(url_str)
    params: list[tuple[str, str]] = []
    if parsed.query:
        qs = parse_qs(parsed.query, keep_blank_values=True)
        for key in qs.keys():
            k = key.strip()
            if k and re.match(r"^[a-zA-Z0-9_\-\.\[\]]+$", k):
                params.append((k, "query"))
    return params


def _extract_form_inputs(html: str) -> list[tuple[str, str]]:
    """Extracts form field parameters from HTML input/select/textarea tags."""
    if not html:
        return []
    params: list[tuple[str, str]] = []
    for m in re.finditer(r'<input[^>]+name=["\']([^"\']+)["\']', html, re.IGNORECASE):
        name = m.group(1).strip()
        if name:
            params.append((name, "body"))
    for m in re.finditer(r'<textarea[^>]+name=["\']([^"\']+)["\']', html, re.IGNORECASE):
        name = m.group(1).strip()
        if name:
            params.append((name, "body"))
    for m in re.finditer(r'<select[^>]+name=["\']([^"\']+)["\']', html, re.IGNORECASE):
        name = m.group(1).strip()
        if name:
            params.append((name, "body"))
    return params


def _extract_form_actions(html: str, page_url: str) -> List[Dict[str, Any]]:
    """Dynamically extracts all <form> actions, methods, fields, and hidden tokens from HTML.
    
    Returns a list of discovered form descriptors, each containing:
    - action_url: resolved absolute URL for the form action
    - method: HTTP method (GET/POST)
    - fields: list of {name, type, value?} dicts
    - has_password_field: whether the form contains a password input
    - has_username_field: whether a username/email-like input was detected
    - username_field_name: the actual field name for username input
    - password_field_name: the actual field name for password input
    - hidden_tokens: dict of hidden input name→value pairs (for CSRF)
    - is_login_form: heuristic determination of whether this is an auth form
    """
    if not html:
        return []

    forms: List[Dict[str, Any]] = []

    # Match <form ...> ... </form> blocks
    form_pattern = re.compile(
        r'<form\b([^>]*)>(.*?)</form>',
        re.IGNORECASE | re.DOTALL,
    )

    for fm in form_pattern.finditer(html):
        attrs_str = fm.group(1)
        body = fm.group(2)

        # Extract action URL
        action_match = re.search(r'action=["\']([^"\']*)["\']', attrs_str, re.IGNORECASE)
        raw_action = action_match.group(1).strip() if action_match else ""
        action_url = urljoin(page_url, raw_action) if raw_action else page_url

        # Extract method
        method_match = re.search(r'method=["\']([^"\']+)["\']', attrs_str, re.IGNORECASE)
        method = (method_match.group(1).strip().upper() if method_match else "GET")

        # Extract all input fields
        fields: List[Dict[str, str]] = []
        hidden_tokens: Dict[str, str] = {}
        has_password = False
        has_username = False
        password_field_name = ""
        username_field_name = ""

        username_indicators = (
            "user", "login", "email", "account", "name", "nim", "nik",
            "identity", "username", "uname", "userid", "nip",
        )
        password_indicators = ("password", "passwd", "pwd", "pass", "sandi", "kata_sandi")

        for inp in re.finditer(r'<input\b([^>]*)/?>', body, re.IGNORECASE):
            inp_attrs = inp.group(1)
            name_m = re.search(r'name=["\']([^"\']+)["\']', inp_attrs, re.IGNORECASE)
            type_m = re.search(r'type=["\']([^"\']+)["\']', inp_attrs, re.IGNORECASE)
            value_m = re.search(r'value=["\']([^"\']*)["\']', inp_attrs, re.IGNORECASE)

            f_name = name_m.group(1).strip() if name_m else ""
            f_type = (type_m.group(1).strip().lower() if type_m else "text")
            f_value = value_m.group(1).strip() if value_m else ""

            if not f_name:
                continue

            fields.append({"name": f_name, "type": f_type, "value": f_value})

            if f_type == "hidden" and f_value:
                hidden_tokens[f_name] = f_value

            if f_type == "password":
                has_password = True
                password_field_name = f_name
            elif f_type in ("text", "email") and any(
                ind in f_name.lower() for ind in username_indicators
            ):
                has_username = True
                username_field_name = f_name

        # Determine if this is a login form
        is_login = has_password and (has_username or len(fields) <= 5)

        forms.append({
            "action_url": action_url,
            "method": method,
            "fields": fields,
            "has_password_field": has_password,
            "has_username_field": has_username,
            "username_field_name": username_field_name,
            "password_field_name": password_field_name,
            "hidden_tokens": hidden_tokens,
            "is_login_form": is_login,
        })

    return forms


async def _harvest_passive_urls(root_domain: str, host: str) -> List[str]:
    """Harvests historical endpoints from AlienVault OTX & Archive.org Wayback CDX API."""
    urls: Set[str] = set()

    # 1. Archive.org Wayback CDX
    try:
        wayback_url = f"http://web.archive.org/cdx/search/cdx?url=*.{host}/*&output=json&fl=original&collapse=urlkey&limit=150"
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(wayback_url)
            if resp.status_code == 200:
                data = resp.json()
                for row in data[1:]:  # skip header
                    if row and len(row) > 0:
                        raw = row[0].strip()
                        if raw.startswith(("http://", "https://")):
                            urls.add(raw)
    except Exception as e:
        logger.debug("Wayback CDX passive URL harvest error: %s", e)

    # 2. AlienVault OTX URL list
    try:
        otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{root_domain}/url_list?limit=50"
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(otx_url)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("url_list", []):
                    u = item.get("url", "").strip()
                    if u and host in u and u.startswith(("http://", "https://")):
                        urls.add(u)
    except Exception as e:
        logger.debug("AlienVault OTX passive URL harvest error: %s", e)

    return list(urls)


def _extract_js_endpoints(js_text: str, base_url: str) -> List[str]:
    """
    Extracts API routes, REST endpoints, and paths from JavaScript bundle content.
    Identifies patterns like:
    - "/api/v1/users", "/auth/login"
    - fetch("/endpoint"), axios.get("/path")
    - path: "/route"
    """
    if not js_text or len(js_text) < 10:
        return []

    endpoints: Set[str] = set()

    # Regex for API paths in quotes
    pattern_quotes = r'["\'](/(?:api|v[0-9]|graphql|auth|admin|user|dashboard|service|webhook|upload|download)/[a-zA-Z0-9_\-\./\?=&]+)["\']'
    for match in re.finditer(pattern_quotes, js_text):
        path = match.group(1)
        if not path.endswith((".js", ".css", ".png", ".jpg", ".svg")):
            endpoints.add(urljoin(base_url, path))

    # Regex for Axios / Fetch / Angular / jQuery AJAX calls
    pattern_ajax = r'(?:get|post|put|delete|patch|fetch|url)\s*[:\(]\s*["\']([^"\'#\s>]+)["\']'
    for match in re.finditer(pattern_ajax, js_text, re.IGNORECASE):
        raw_target = match.group(1).strip()
        if raw_target.startswith("/"):
            endpoints.add(urljoin(base_url, raw_target))
        elif raw_target.startswith(("http://", "https://")):
            endpoints.add(raw_target)

    return list(endpoints)


def _parse_directory_listing(html: str, directory_url: str) -> List[str]:
    """Parse Apache, Nginx, Lighttpd, and Python HTTP HTML directory listings dynamically."""
    if not html or len(html) < 20:
        return []

    is_dir_listing = (
        "index of /" in html.lower()
        or "<title>index of" in html.lower()
        or "directory listing for" in html.lower()
        or "[to parent directory]" in html.lower()
        or "parent directory</a>" in html.lower()
        or '<table id="indexlist"' in html.lower()
        or 'class="directory"' in html.lower()
    )
    if not is_dir_listing:
        return []

    discovered_files: Set[str] = set()
    for match in re.finditer(r'<a\s+[^>]*href=["\']([^"\'?#]+)["\']', html, re.IGNORECASE):
        href = match.group(1).strip()
        if href in ("../", "./", "/", "") or href.startswith(("?", "#", "javascript:")):
            continue
        if href.startswith("/"):
            file_url = urljoin(directory_url, href)
        else:
            file_url = urljoin(directory_url.rstrip("/") + "/", href)
        discovered_files.add(file_url)

    return list(discovered_files)


async def _in_flight_fuzz_url(ctx: ScanContext, host: str, asset_id: str, endpoint_url: str, params: List[Dict[str, str]]) -> None:
    """Performs continuous in-flight fuzzing (SQLi, XSS) concurrently while crawler continues discovering new pages."""
    try:
        from app.validation.sqli import sqli_validator
        from app.validation.xss import xss_validator
        from app.scanners.security import _process_and_save_validated_finding
        from app.validation.result import NormalizedValidationResult

        # 1. Continuous SQL Injection Live Test
        sqli_cands = await sqli_validator.validate_url(endpoint_url, params)
        if sqli_cands:
            async with AsyncSessionLocal() as session:
                for cand in sqli_cands:
                    norm_res = NormalizedValidationResult(
                        adapter_name="sqli_validator_in_flight",
                        vulnerability_type="sql_injection",
                        title=f"SQL Injection on '{cand.parameter}' ({cand.technique}, {cand.db_engine})",
                        severity="CRITICAL",
                        confidence=cand.confidence,
                        evidence_level="E3" if cand.confidence == "CONFIRMED" else "E2",
                        target_host=host,
                        endpoint_url=endpoint_url,
                        parameter=cand.parameter,
                        cwe_id="CWE-89",
                        description=f"Continuous in-flight fuzzing detected SQL Injection on parameter '{cand.parameter}' using {cand.technique} for {cand.db_engine}.",
                        impact_matrix={"confidentiality": "CRITICAL", "integrity": "CRITICAL", "availability": "HIGH", "auth_bypass": "POSSIBLE"},
                        remediation="Use parameterized queries and ORM prepared statements.",
                        poc_command=cand.evidence.get("poc_curl") if isinstance(cand.evidence, dict) else f"curl -i -s -k '{endpoint_url}'",
                        poc_payload=cand.evidence.get("probe", "") if isinstance(cand.evidence, dict) else "",
                        reproduction_steps=cand.reproduction_steps,
                        request_metadata={"url": endpoint_url, "parameter": cand.parameter, "db_engine": cand.db_engine},
                        response_metadata=cand.evidence if isinstance(cand.evidence, dict) else {},
                    )
                    await _process_and_save_validated_finding(ctx, session, asset_id, host, norm_res)
                    await session.commit()
                    logger.info("IN-FLIGHT CONFIRMED SQLi on %s: %s", endpoint_url, cand.parameter)

        # 2. Continuous XSS Live Test
        xss_cands = await xss_validator.validate_url(endpoint_url, params)
        if xss_cands:
            async with AsyncSessionLocal() as session:
                for cand in xss_cands:
                    norm_res = NormalizedValidationResult(
                        adapter_name="xss_validator_in_flight",
                        vulnerability_type="cross_site_scripting",
                        title=f"Cross-Site Scripting (XSS) on '{cand.parameter}' ({cand.context})",
                        severity="HIGH",
                        confidence=cand.confidence,
                        evidence_level="E3" if cand.confidence == "CONFIRMED" else "E2",
                        target_host=host,
                        endpoint_url=endpoint_url,
                        parameter=cand.parameter,
                        cwe_id="CWE-79",
                        description=f"Continuous in-flight fuzzing detected reflected XSS on '{cand.parameter}' in {cand.context} context.",
                        impact_matrix={"confidentiality": "HIGH", "integrity": "HIGH", "availability": "LOW"},
                        remediation="Context-aware HTML entity encoding and strict Content Security Policy (CSP).",
                        poc_command=cand.evidence.get("poc_curl") if isinstance(cand.evidence, dict) else f"curl -i -s -k '{endpoint_url}'",
                        poc_payload=cand.evidence.get("probe", "") if isinstance(cand.evidence, dict) else "",
                        reproduction_steps=cand.reproduction_steps,
                        request_metadata={"url": endpoint_url, "parameter": cand.parameter},
                        response_metadata=cand.evidence if isinstance(cand.evidence, dict) else {},
                    )
                    await _process_and_save_validated_finding(ctx, session, asset_id, host, norm_res)
                    await session.commit()
                    logger.info("IN-FLIGHT CONFIRMED XSS on %s: %s", endpoint_url, cand.parameter)
    except Exception as exc:
        logger.debug("In-flight fuzzing error on %s: %s", endpoint_url, exc)


async def crawl_and_discover_asset(ctx: ScanContext, db: AsyncSession, asset: Asset, root_domain: str, is_many_hosts: bool = False) -> None:
    """Discovers URLs, Endpoints, and Parameters for a single active asset dynamically."""
    host = asset.hostname
    if not host or not ctx.scope.host_allowed(host):
        return
    if asset.ip and not ctx.scope.ip_allowed(asset.ip):
        await ctx.emit(
            "scope.ip_blocked",
            f"Web discovery blocked for non-authorized resolved address on {host}.",
            host=host,
            severity="warn",
        )
        return

    base_urls = [f"https://{host}/", f"http://{host}/"]
    existing_urls = (await db.execute(
        select(URL).where(URL.asset_id == asset.id)
    )).scalars().all()
    if existing_urls:
        base_urls = list({u.url for u in existing_urls})

    # 1. Fast Liveness Check — avoid wasting budgets on dead/unresponsive hosts
    is_live = False
    for b in base_urls:
        resp_test = await fetch_http(b, timeout=3.5)
        if resp_test is not None:
            is_live = True
            break
    if not is_live:
        logger.debug("Asset %s is unreachable on HTTP/HTTPS. Skipping heavy web crawl.", host)
        return

    # 1b. Detect Soft-404 / Custom 404 Baseline
    soft_404_baseline = await soft_404_detector.get_baseline(host)
    is_soft_404 = soft_404_baseline.get("is_soft_404", False)

    seen_urls: Set[str] = {u.rstrip("/") for u in base_urls}
    to_probe_queue: List[str] = []

    # 2. Add Passive URL Discoveries
    passive_urls = await _harvest_passive_urls(root_domain, host)
    for pu in passive_urls:
        p_norm = pu.rstrip("/")
        if p_norm not in seen_urls and ctx.scope.host_allowed(urlparse(pu).hostname or ""):
            seen_urls.add(p_norm)
            to_probe_queue.append(pu)

    if passive_urls:
        await ctx.emit(
            "crawl.passive",
            f"Harvested {len(passive_urls)} historical endpoints from Wayback / Threat Intelligence for {host}",
            count=len(passive_urls),
            host=host,
            severity="info",
        )

    # 3. Add Technology-Aware & Dynamic Target-Aware Seed Endpoints (Dirsearch / Subfinder style)
    techs = (await db.execute(
        select(Technology).where(Technology.asset_id == asset.id)
    )).scalars().all()
    tech_names = [t.name.lower() for t in techs]

    seed_paths = list(TARGETED_SEED_PATHS)
    for t_key, t_paths in FRAMEWORK_DISCOVERY_MAP.items():
        if any(t_key in tn for tn in tech_names):
            seed_paths.extend(t_paths)

    # Dynamic target name mutations (e.g. host: preview.owasp-juice.shop -> juice, preview, owasp-juice)
    clean_h = host.split(":")[0].lower()
    h_parts = clean_h.split(".")
    sub = h_parts[0] if len(h_parts) > 1 else clean_h
    dom = h_parts[-2] if len(h_parts) >= 2 else clean_h
    target_mutations = [
        f"/{sub}.sql", f"/{dom}.sql", f"/database/{sub}.sql", f"/database/{dom}.sql",
        f"/backup_{sub}.sql", f"/dump_{sub}.sql", f"/db_{sub}.sql",
        f"/{sub}.zip", f"/{dom}.zip", f"/backup_{sub}.zip", f"/{sub}.tar.gz",
        f"/{sub}.csv", f"/{dom}.csv", f"/export_{sub}.csv", f"/database/{sub}.csv",
        f"/{sub}_backup.sql", f"/{sub}_db.sql", f"/{sub}_data.csv",
    ]
    seed_paths.extend(target_mutations)

    for base in base_urls:
        for path in seed_paths:
            cand = urljoin(base, path)
            norm = cand.rstrip("/")
            if norm not in seen_urls:
                seen_urls.add(norm)
                to_probe_queue.append(cand)

        # 4. Check robots.txt and sitemap.xml dynamically
        robots_url = urljoin(base, "/robots.txt")
        resp = await fetch_http(robots_url, timeout=4.0)
        if resp and resp.status_code == 200 and resp.text:
            for line in resp.text.splitlines():
                if ":" in line:
                    prefix, val = line.split(":", 1)
                    p_lower = prefix.strip().lower()
                    if p_lower in ("disallow", "allow"):
                        p = val.strip()
                        if p and p != "/" and not p.startswith("*"):
                            cand = urljoin(base, p)
                            norm = cand.rstrip("/")
                            if norm not in seen_urls:
                                seen_urls.add(norm)
                                to_probe_queue.append(cand)
                    elif p_lower == "sitemap":
                        sitemap_url = val.strip()
                        if sitemap_url and sitemap_url not in seen_urls:
                            seen_urls.add(sitemap_url.rstrip("/"))
                            to_probe_queue.append(sitemap_url)

        # 5. Execute Dirsearch Tool Adapter selectively on primary/high-value targets (V10)
        # Avoid exhausting scan runtime budgets on dozens of secondary/leaf subdomains
        is_high_value_host = (
            host == root_domain
            or host == f"www.{root_domain}"
            or any(kw in host.lower() for kw in ["siakad", "portal", "admin", "api", "app", "login", "webmail", "elearning", "moodle", "kuesioner", "auth"])
            or (asset.depth == 0)
            or not is_many_hosts
        )

        if is_high_value_host:
            try:
                ds_adapter = DirsearchAdapter()
                await ctx.emit(
                    "tool.active",
                    f"⚡ Dirsearch active on {base} (9,681 paths dictionary)...",
                    tool="dirsearch",
                    target=base,
                    host=host,
                    severity="info",
                )
                ds_res = await ds_adapter.execute({"target_url": base, "threads": 20, "max_time": 30})
                ds_hits = ds_res.get("discovered_urls", [])
                if ds_hits:
                    await ctx.emit(
                        "dirsearch.results",
                        f"🎯 Dirsearch discovered {len(ds_hits)} live endpoint(s) on {host}",
                        count=len(ds_hits),
                        host=host,
                        severity="info",
                    )
                    for hit in ds_hits:
                        hit_url = hit.get("url")
                        if hit_url and hit_url.rstrip("/") not in seen_urls:
                            seen_urls.add(hit_url.rstrip("/"))
                            to_probe_queue.append(hit_url)
            except Exception as ds_err:
                logger.debug("Dirsearch adapter execution fallback on %s: %s", host, ds_err)

        # 6. Execute Katana Tool Adapter for fast JS-aware crawling (V10)
        try:
            kt_adapter = KatanaAdapter()
            kt_res = await kt_adapter.execute({"target_url": base, "depth": 2})
            kt_endpoints = kt_res.get("endpoints", [])
            if kt_endpoints:
                await ctx.emit(
                    "tool.active",
                    f"🕷️ Katana spider crawled {len(kt_endpoints)} endpoint(s) on {host}",
                    tool="katana",
                    count=len(kt_endpoints),
                    host=host,
                    severity="info",
                )
                for ep in kt_endpoints:
                    if ep and ep.rstrip("/") not in seen_urls and ctx.scope.host_allowed(urlparse(ep).hostname or ""):
                        seen_urls.add(ep.rstrip("/"))
                        to_probe_queue.append(ep)
        except Exception as kt_err:
            logger.debug("Katana adapter execution fallback on %s: %s", host, kt_err)

    # Limit maximum URLs per host according to scan budget
    cap = min(len(to_probe_queue), settings.max_urls_per_scan // max(1, settings.max_web_hosts))
    probed_batch = to_probe_queue[:cap]

    resource_guard.reclaim_memory()
    sem = asyncio.Semaphore(12)
    discovered_js_files: Set[str] = set()

    async def probe_endpoint(target_url: str, depth: int = 0):
        async with sem:
            await ctx.rate_limiter.wait()
            resp = await fetch_http(target_url, timeout=settings.http_timeout_seconds)
            if resp is None:
                return

            status = resp.status_code
            parsed = urlparse(target_url)
            port_num = parsed.port or (443 if parsed.scheme == "https" else 80)
            title = extract_title(resp.text) if resp.text else None
            content_type = (resp.headers.get("content-type") or "").split(";")[0].strip()[:100]

            # Soft-404 & Single Page Application (SPA) Catch-All Anti-Noise Filter (§44):
            # If server is an SPA or returns 200 with index.html for non-existent files (/www.zip, /backup.sql)
            if status == 200 and soft_404_detector.is_soft_404(target_url, status, resp.text, title=title):
                logger.debug("Soft-404 / SPA catch-all fallback discarded on %s", target_url)
                return

            # WAF, Bot Challenge & Suspended Domain Protection (§44 Anti-Noise):
            is_waf, waf_reason = is_waf_or_error_page(status, resp.text, content_type, title or "")
            is_suspended = "suspended" in (title or "").lower() or "suspended" in (resp.text or "")[:1500].lower() or "cgi-sys/suspendedpage" in (resp.text or "").lower()
            if (is_waf or is_suspended) and status == 200:
                # Target returned a WAF challenge or Suspended holding page
                logger.info("Non-active page detected on %s: %s (Suspended: %s)", target_url, waf_reason or "Suspended Page", is_suspended)
                if any(sp in parsed.path.lower() for sp in [".git", ".env", "backup", "phpinfo"]):
                    return

            async with AsyncSessionLocal() as session:
                clean_target_url = sanitize_text(target_url)
                clean_title = sanitize_text(title)
                clean_ct = sanitize_text(content_type)
                clean_path = sanitize_text(parsed.path or "/")

                if is_suspended:
                    clean_ct = "suspended_page"
                    clean_title = clean_title or "This site is currently suspended"

                # If WAF detected, save technology on asset
                if is_waf and (title and "moment" in title.lower() or "pure" in (resp.text or "").lower() or "cloudflare" in (resp.text or "").lower()):
                    waf_name = "Cloudflare / Pure 360 WAF" if "pure" in (resp.text or "").lower() or "moment" in (title or "").lower() else "Web Application Firewall"
                    existing_tech = (await session.execute(
                        select(Technology).where(Technology.asset_id == asset.id, Technology.name == waf_name)
                    )).scalar_one_or_none()
                    if not existing_tech:
                        session.add(Technology(
                            asset_id=asset.id,
                            name=waf_name,
                            category="WAF",
                            confidence=0.95,
                            evidence=f"Detected via challenge page: {clean_title or 'Challenge Portal'}",
                        ))
                        await session.flush()

                # Upsert URL
                existing = (await session.execute(
                    select(URL).where(URL.asset_id == asset.id, URL.url == clean_target_url)
                )).scalar_one_or_none()

                url_record = existing
                if not url_record:
                    url_record = URL(
                        asset_id=asset.id,
                        url=clean_target_url,
                        scheme=parsed.scheme,
                        host=host,
                        port=port_num,
                        path=clean_path,
                        query=parsed.query,
                        status_code=status,
                        content_type="suspended_page" if is_suspended else ("waf_challenge" if is_waf and status == 200 else clean_ct),
                        title=clean_title,
                    )
                    session.add(url_record)
                    await session.flush()

                if (status < 400 or status in (401, 403)) and not (is_waf and status == 200 and parsed.path != "/"):
                    await ctx.emit(
                        "url.discovered",
                        f"Endpoint: {clean_target_url} [{status}]" + (f" — \"{clean_title}\"" if clean_title else ""),
                        url=clean_target_url,
                        status_code=status,
                        host=host,
                        title=clean_title,
                        asset_id=asset.id,
                        severity="info" if status < 400 else "warn",
                    )

                # Parameter Extraction (Query string & HTML forms - only if not WAF challenge page)
                found_params = _extract_parameters_from_url(clean_target_url)
                if resp.text and status == 200 and not is_waf:
                    found_params.extend(_extract_form_inputs(resp.text))

                for raw_param_name, loc in set(found_params):
                    param_name = sanitize_text(raw_param_name)
                    existing_param = (await session.execute(
                        select(Parameter).where(
                            Parameter.url_id == url_record.id,
                            Parameter.name == param_name,
                            Parameter.location == loc,
                        )
                    )).scalar_one_or_none()

                    if not existing_param:
                        session.add(Parameter(
                            url_id=url_record.id,
                            name=param_name,
                            location=loc,
                            type="string",
                            source="crawler",
                            confidence=0.95,
                        ))
                        await ctx.emit(
                            "parameter.discovered",
                            f"Parameter [{loc}]: '{param_name}' detected on {clean_path}",
                            name=param_name,
                            location=loc,
                            url=clean_target_url,
                            asset_id=asset.id,
                            severity="info",
                        )

                # Real-Time Continuous In-Flight Vulnerability Escalation (§19-§22)
                # As soon as parameters or API query routes are found, test SQLi/XSS live in background
                if status == 200 and not is_waf and ctx.profile in ("standard", "deep", "custom") and found_params:
                    param_list = [{"name": p[0], "location": p[1]} for p in set(found_params)]
                    asyncio.create_task(_in_flight_fuzz_url(ctx, host, asset.id, clean_target_url, param_list))

                # Dynamic Login Form Discovery — tag URLs containing auth forms
                if resp.text and status == 200 and not is_waf and not is_suspended:
                    discovered_forms = _extract_form_actions(resp.text, target_url)
                    login_forms = [f for f in discovered_forms if f["is_login_form"]]
                    if login_forms:
                        # Tag this URL as a login form endpoint
                        url_record.content_type = "login_form"
                        await session.flush()
                        for lf in login_forms:
                            await ctx.emit(
                                "auth.form_discovered",
                                f"🔐 Login form discovered on {clean_target_url} "
                                f"(action: {lf['action_url']}, "
                                f"user_field: {lf['username_field_name'] or 'auto'}, "
                                f"pass_field: {lf['password_field_name']})",
                                url=clean_target_url,
                                form_action=lf["action_url"],
                                method=lf["method"],
                                username_field=lf["username_field_name"],
                                password_field=lf["password_field_name"],
                                hidden_tokens=lf["hidden_tokens"],
                                fields=[fd["name"] for fd in lf["fields"]],
                                host=host,
                                asset_id=asset.id,
                                severity="info",
                            )
                            logger.info(
                                "Dynamic auth form discovered: %s (action=%s, user=%s, pass=%s)",
                                clean_target_url, lf["action_url"],
                                lf["username_field_name"], lf["password_field_name"],
                            )

                # Deep Recursive Crawling & JavaScript Bundle Discovery
                new_links_to_crawl: List[str] = []

                if resp.text and len(resp.text) < 1_500_000 and status == 200 and not is_waf and not is_suspended:
                    # 1. Dynamic Directory Listing Discovery (Index of /...)
                    dir_files = _parse_directory_listing(resp.text, target_url)
                    if dir_files:
                        await ctx.emit(
                            "crawl.directory_listing",
                            f"📂 Directory Listing exposed on {clean_target_url} — found {len(dir_files)} file(s)",
                            url=clean_target_url,
                            file_count=len(dir_files),
                            host=host,
                            asset_id=asset.id,
                            severity="warn",
                        )
                        for df_url in dir_files:
                            df_norm = df_url.rstrip("/")
                            if df_norm not in seen_urls and len(seen_urls) < settings.max_urls_per_scan:
                                seen_urls.add(df_norm)
                                new_links_to_crawl.append(df_url)

                    # 2. HTML Links & Actions
                    for match in re.finditer(r'(?:href|src|action|data-url)=["\']([^"\'#\s>]+)["\']', resp.text, re.IGNORECASE):
                        raw_link = match.group(1).strip()
                        if raw_link.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
                            continue
                        full_link = urljoin(target_url, raw_link)
                        p_link = urlparse(full_link)

                        if p_link.scheme in ("http", "https") and p_link.hostname == host:
                            norm_link = full_link.rstrip("/")

                            # Collect JS files for AST/Route scraping
                            if p_link.path.lower().endswith(".js") and norm_link not in discovered_js_files:
                                discovered_js_files.add(norm_link)

                            if norm_link not in seen_urls and len(seen_urls) < settings.max_urls_per_scan:
                                seen_urls.add(norm_link)
                                new_links_to_crawl.append(full_link)

                await session.commit()

                # Dynamic Parameter Mining on prominent functional endpoints (e.g. search, login, api)
                if status == 200 and any(kw in clean_path.lower() for kw in ["api", "search", "detail", "item", "view", "page", "user"]):
                    await mine_parameters_for_url(ctx, session, url_record)

                # Prioritize sensitive files (.sql, .csv, .log) and auth endpoints in crawl queue
                if depth < 2 and new_links_to_crawl:
                    def _crawl_priority(link: str) -> int:
                        l = link.lower()
                        if any(l.endswith(ext) for ext in [".sql", ".csv", ".tsv", ".log", ".dump", ".bak", ".zip", ".tar.gz", ".env"]) or "/.env" in l:
                            return 0
                        if any(kw in l for kw in ["auth", "admin", "login", "database", "export", "backup"]):
                            return 1
                        return 2

                    new_links_to_crawl.sort(key=_crawl_priority)
                    sub_tasks = [probe_endpoint(nl, depth=depth + 1) for nl in new_links_to_crawl[:25]]
                    await asyncio.gather(*sub_tasks, return_exceptions=True)

    await asyncio.gather(*[probe_endpoint(u) for u in probed_batch], return_exceptions=True)

    # 5. Scrape Discovered JavaScript Bundles for API Routes & Hidden Endpoints
    if discovered_js_files:
        await ctx.emit(
            "crawl.js",
            f"Analyzing {len(discovered_js_files)} JavaScript bundle(s) for REST API & GraphQL routes...",
            count=len(discovered_js_files),
            host=host,
            severity="info",
        )

        new_discovered_urls = []

        async def analyze_js_file(js_url: str):
            async with sem:
                resp = await fetch_http(js_url, timeout=settings.http_timeout_seconds)
                if resp and resp.status_code == 200 and resp.text:
                    # 1. Regex Heuristic Extractor
                    extracted_routes = _extract_js_endpoints(resp.text, js_url)
                    for r_url in extracted_routes:
                        p_r = urlparse(r_url)
                        if p_r.hostname == host:
                            r_norm = r_url.rstrip("/")
                            if r_norm not in seen_urls:
                                seen_urls.add(r_norm)
                                new_discovered_urls.append((r_url, p_r))

                    # 2. Live NineRouter LLM Multi-Model Combo JS Intelligence (Only on deep profiles to save resources)
                    from app.intelligence.llm_client import llm_client
                    if llm_client.is_configured and len(resp.text) > 120 and ctx.profile in ("deep", "deep_bug_hunt", "pentest", "adversary_simulation"):
                        try:
                            ai_js = await llm_client.analyze_javascript_code(resp.text, js_url)
                            for ep in (ai_js.get("endpoints") or []):
                                if isinstance(ep, str) and (ep.startswith("/") or ep.startswith("http")):
                                    full_ep = ep if ep.startswith("http") else urljoin(js_url, ep)
                                    p_ep = urlparse(full_ep)
                                    if p_ep.hostname == host or not p_ep.hostname:
                                        ep_norm = full_ep.rstrip("/")
                                        if ep_norm not in seen_urls:
                                            seen_urls.add(ep_norm)
                                            new_discovered_urls.append((full_ep, p_ep))
                        except Exception as ai_js_err:
                            logger.debug("AI JS analysis note for %s: %s", js_url, ai_js_err)

        await asyncio.gather(*[analyze_js_file(ju) for ju in list(discovered_js_files)[:25]], return_exceptions=True)

        if new_discovered_urls:
            async with AsyncSessionLocal() as session:
                for r_url, p_r in new_discovered_urls:
                    clean_r = sanitize_text(r_url)
                    session.add(URL(
                        asset_id=asset.id,
                        url=clean_r,
                        scheme=p_r.scheme,
                        host=host,
                        port=p_r.port or (443 if p_r.scheme == "https" else 80),
                        path=sanitize_text(p_r.path or "/"),
                        status_code=None,
                        content_type="js_extracted_endpoint",
                    ))
                    await ctx.emit(
                        "url.discovered",
                        f"JS Discovered Route: {clean_r}",
                        url=clean_r,
                        host=host,
                        asset_id=asset.id,
                        severity="info",
                    )
                await session.commit()


async def run(ctx: ScanContext, db: AsyncSession, root_domain: str) -> None:
    """Intelligent Dynamic Web Crawler & Route Mining Pipeline."""
    if ctx.profile == "passive":
        return

    await ctx.emit("scan.web", f"Starting intelligent dynamic web & parameter discovery for {root_domain}", severity="info")

    assets = (await db.execute(
        select(Asset).where(
            Asset.scan_id == ctx.scan_id,
            Asset.asset_type.in_(["domain", "subdomain"]),
        )
    )).scalars().all()

    # Prioritize root domain and high-value functional portals over leaf/CDN subdomains
    def _asset_priority(a: Asset) -> int:
        h = (a.hostname or "").lower()
        if h == root_domain or h == f"www.{root_domain}":
            return 0
        if any(kw in h for kw in ["siakad", "portal", "admin", "api", "app", "login", "auth", "moodle", "elearning", "kuesioner"]):
            return 1
        return 2

    sorted_assets = sorted(assets, key=_asset_priority)[: settings.max_web_hosts]
    total_count = len(sorted_assets)
    sem = asyncio.Semaphore(6)

    async def _crawl_asset_sem(a: Asset):
        async with sem:
            async with AsyncSessionLocal() as session:
                try:
                    await asyncio.wait_for(
                        crawl_and_discover_asset(ctx, session, a, root_domain, is_many_hosts=(total_count > 4)),
                        timeout=45.0,  # Max 45s per individual asset crawl
                    )
                except asyncio.TimeoutError:
                    logger.debug("Asset %s crawl exceeded 45s per-asset budget", a.hostname)
                except Exception as exc:
                    logger.debug("Asset %s crawl error: %s", a.hostname, exc)

    try:
        # Cap total web crawl phase to 600s max (10 minutes)
        await asyncio.wait_for(
            asyncio.gather(*[_crawl_asset_sem(a) for a in sorted_assets], return_exceptions=True),
            timeout=600.0,
        )
    except asyncio.TimeoutError:
        logger.info("Web discovery phase reached maximum allocated budget (600s). Proceeding to next phase.")
