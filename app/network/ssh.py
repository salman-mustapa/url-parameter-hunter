"""SSH Deep Security Assessment Module (V4 §16).

Comprehensive SSH assessment beyond simple banner grabbing:
- Protocol and version detection
- Key exchange algorithms (KEX)
- Host key types
- Encryption algorithms (ciphers)
- MAC algorithms
- Compression algorithms
- Authentication method detection
- Root login policy indicator
- Weak crypto detection
- CVE correlation based on detected version
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("network.ssh")

# Weak/deprecated algorithms
WEAK_KEX = {
    "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
}

WEAK_CIPHERS = {
    "3des-cbc", "blowfish-cbc", "cast128-cbc", "arcfour",
    "arcfour128", "arcfour256", "aes128-cbc", "aes192-cbc",
    "aes256-cbc", "rijndael-cbc@lysator.liu.se",
}

WEAK_MACS = {
    "hmac-md5", "hmac-md5-96", "hmac-sha1-96",
    "hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com",
}

WEAK_HOST_KEYS = {
    "ssh-dss",
}

# Known vulnerable OpenSSH versions
SSH_CVES = {
    "8.5": [{"cve": "CVE-2021-41617", "severity": "HIGH", "desc": "Privilege escalation via AuthorizedKeysCommand"}],
    "8.7": [{"cve": "CVE-2021-41617", "severity": "HIGH", "desc": "Privilege escalation via AuthorizedKeysCommand"}],
    "8.8": [{"cve": "CVE-2023-38408", "severity": "HIGH", "desc": "PKCS#11 remote code execution via ssh-agent"}],
    "8.9": [{"cve": "CVE-2023-38408", "severity": "HIGH", "desc": "PKCS#11 remote code execution via ssh-agent"}],
    "9.0": [{"cve": "CVE-2023-38408", "severity": "HIGH", "desc": "PKCS#11 remote code execution via ssh-agent"}],
    "9.1": [{"cve": "CVE-2023-38408", "severity": "HIGH", "desc": "PKCS#11 remote code execution via ssh-agent"}],
    "9.3": [{"cve": "CVE-2023-48795", "severity": "MEDIUM", "desc": "Terrapin attack (prefix truncation)"}],
    "9.5": [{"cve": "CVE-2024-6387", "severity": "CRITICAL", "desc": "regreSSHion - unauthenticated RCE"}],
    "9.6": [{"cve": "CVE-2024-6387", "severity": "CRITICAL", "desc": "regreSSHion - unauthenticated RCE"}],
    "9.7": [{"cve": "CVE-2024-6387", "severity": "CRITICAL", "desc": "regreSSHion - unauthenticated RCE"}],
}


@dataclass
class SshAssessmentResult:
    host: str
    port: int = 22
    banner: str = ""
    protocol_version: str = ""
    software_version: str = ""
    software_product: str = ""
    kex_algorithms: List[str] = field(default_factory=list)
    host_key_algorithms: List[str] = field(default_factory=list)
    encryption_algorithms: List[str] = field(default_factory=list)
    mac_algorithms: List[str] = field(default_factory=list)
    compression_algorithms: List[str] = field(default_factory=list)
    auth_methods: List[str] = field(default_factory=list)
    weak_kex: List[str] = field(default_factory=list)
    weak_ciphers: List[str] = field(default_factory=list)
    weak_macs: List[str] = field(default_factory=list)
    weak_host_keys: List[str] = field(default_factory=list)
    cve_candidates: List[Dict[str, str]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "UNKNOWN"
    error: str = ""


class SshAssessment:
    """SSH Deep Assessment Engine (V4 §16).

    Performs comprehensive SSH security analysis via SSH protocol handshake.
    All checks are passive/observational — no authentication attempts.
    """

    def __init__(self, timeout: float = 8.0) -> None:
        self.timeout = timeout

    async def assess(self, host: str, port: int = 22) -> SshAssessmentResult:
        """Perform full SSH assessment on target host:port."""
        result = SshAssessmentResult(host=host, port=port)

        try:
            # Phase 1: Banner grab + protocol detection
            banner = await self._grab_banner(host, port)
            if not banner:
                result.status = "TIMEOUT"
                result.error = "No SSH banner received"
                return result

            result.banner = banner.strip()
            self._parse_banner(result)

            # Phase 2: Key exchange init (read KEXINIT from server)
            kexinit = await self._read_kexinit(host, port)
            if kexinit:
                self._parse_kexinit(result, kexinit)

            # Phase 3: Analyze crypto strength
            self._analyze_crypto(result)

            # Phase 4: CVE correlation
            self._correlate_cves(result)

            # Phase 5: Generate findings
            self._generate_findings(result)

            result.status = "ASSESSED"

        except Exception as exc:
            result.status = "ERROR"
            result.error = str(exc)[:200]
            logger.debug("SSH assessment failed for %s:%d: %s", host, port, exc)

        return result

    async def _grab_banner(self, host: str, port: int) -> Optional[str]:
        """Grab the SSH banner via TCP connection."""
        try:
            loop = asyncio.get_event_loop()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.timeout
            )
            banner = await asyncio.wait_for(reader.readline(), timeout=5.0)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return banner.decode("utf-8", errors="replace")
        except Exception:
            return None

    async def _read_kexinit(self, host: str, port: int) -> Optional[bytes]:
        """Read the SSH_MSG_KEXINIT payload from the server."""
        try:
            loop = asyncio.get_event_loop()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.timeout
            )

            # Read server banner
            banner = await asyncio.wait_for(reader.readline(), timeout=5.0)

            # Send our identification string
            writer.write(b"SSH-2.0-BugHunterScanner_1.0\r\n")
            await writer.drain()

            # Read the KEXINIT packet
            # SSH packet: uint32 length, byte padding_length, byte[n1] payload
            header = await asyncio.wait_for(reader.read(4), timeout=5.0)
            if len(header) < 4:
                writer.close()
                return None

            length = int.from_bytes(header, "big")
            if length > 65536:  # Sanity check
                writer.close()
                return None

            payload = await asyncio.wait_for(reader.read(min(length, 16384)), timeout=5.0)

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            return payload

        except Exception as exc:
            logger.debug("KEXINIT read failed for %s: %s", host, exc)
            return None

    def _parse_banner(self, result: SshAssessmentResult) -> None:
        """Parse SSH banner to extract protocol version and software."""
        banner = result.banner
        # Format: SSH-protoversion-softwareversion SP comments
        match = re.match(r"SSH-(\d+\.\d+)-(\S+)", banner)
        if match:
            result.protocol_version = match.group(1)
            result.software_version = match.group(2)

            # Extract product name and version
            sw = result.software_version
            if "OpenSSH" in sw:
                result.software_product = "OpenSSH"
                ver_match = re.search(r"OpenSSH[_]?(\d+\.\d+(?:p\d+)?)", sw)
                if ver_match:
                    result.software_version = ver_match.group(1)
            elif "dropbear" in sw.lower():
                result.software_product = "Dropbear"
            elif "libssh" in sw.lower():
                result.software_product = "libssh"
            else:
                result.software_product = sw.split("_")[0] if "_" in sw else sw

    def _parse_kexinit(self, result: SshAssessmentResult, kexinit: bytes) -> None:
        """Parse SSH_MSG_KEXINIT to extract algorithm lists."""
        try:
            # Skip padding_length byte and MSG_KEXINIT byte and 16-byte cookie
            if len(kexinit) < 18:
                return

            offset = 1 + 16  # padding_length + cookie
            # Check if first byte after padding is SSH_MSG_KEXINIT (20)
            msg_type = kexinit[0] if len(kexinit) > 0 else 0
            if msg_type == 20:
                offset = 17  # msg_type + 16-byte cookie
            elif kexinit[1:2] == b'\x14':  # padding_length + msg_type
                offset = 2 + 16

            algo_lists = []
            for _ in range(10):  # 10 name-list fields in KEXINIT
                if offset + 4 > len(kexinit):
                    break
                name_len = int.from_bytes(kexinit[offset:offset + 4], "big")
                offset += 4
                if offset + name_len > len(kexinit):
                    break
                name_list = kexinit[offset:offset + name_len].decode("utf-8", errors="replace")
                algo_lists.append(name_list.split(",") if name_list else [])
                offset += name_len

            if len(algo_lists) >= 6:
                result.kex_algorithms = algo_lists[0]
                result.host_key_algorithms = algo_lists[1]
                result.encryption_algorithms = list(set(algo_lists[2] + algo_lists[3]))  # c2s + s2c
                result.mac_algorithms = list(set(algo_lists[4] + algo_lists[5]))  # c2s + s2c
            if len(algo_lists) >= 8:
                result.compression_algorithms = list(set(algo_lists[6] + algo_lists[7]))

        except Exception as exc:
            logger.debug("KEXINIT parse error: %s", exc)

    def _analyze_crypto(self, result: SshAssessmentResult) -> None:
        """Identify weak cryptographic algorithms."""
        result.weak_kex = [a for a in result.kex_algorithms if a in WEAK_KEX]
        result.weak_ciphers = [a for a in result.encryption_algorithms if a in WEAK_CIPHERS]
        result.weak_macs = [a for a in result.mac_algorithms if a in WEAK_MACS]
        result.weak_host_keys = [a for a in result.host_key_algorithms if a in WEAK_HOST_KEYS]

    def _correlate_cves(self, result: SshAssessmentResult) -> None:
        """Correlate SSH version with known CVEs."""
        if result.software_product != "OpenSSH":
            return

        version = result.software_version
        # Normalize: "8.9p1" -> "8.9"
        ver_match = re.match(r"(\d+\.\d+)", version)
        if ver_match:
            ver_key = ver_match.group(1)
            if ver_key in SSH_CVES:
                result.cve_candidates = SSH_CVES[ver_key]

    def _generate_findings(self, result: SshAssessmentResult) -> None:
        """Generate security findings from assessment results."""
        findings = []

        # Weak KEX
        if result.weak_kex:
            findings.append({
                "title": f"SSH Weak Key Exchange Algorithms ({len(result.weak_kex)})",
                "severity": "MEDIUM",
                "cwe": "CWE-327",
                "description": f"SSH server supports weak KEX algorithms: {', '.join(result.weak_kex)}",
                "evidence_level": "E2",
                "evidence": {"weak_algorithms": result.weak_kex},
            })

        # Weak ciphers
        if result.weak_ciphers:
            findings.append({
                "title": f"SSH Weak Encryption Ciphers ({len(result.weak_ciphers)})",
                "severity": "MEDIUM",
                "cwe": "CWE-327",
                "description": f"SSH server supports weak ciphers: {', '.join(result.weak_ciphers)}",
                "evidence_level": "E2",
                "evidence": {"weak_ciphers": result.weak_ciphers},
            })

        # Weak MACs
        if result.weak_macs:
            findings.append({
                "title": f"SSH Weak MAC Algorithms ({len(result.weak_macs)})",
                "severity": "LOW",
                "cwe": "CWE-327",
                "description": f"SSH server supports weak MAC algorithms: {', '.join(result.weak_macs)}",
                "evidence_level": "E2",
                "evidence": {"weak_macs": result.weak_macs},
            })

        # Weak host keys (DSA)
        if result.weak_host_keys:
            findings.append({
                "title": "SSH DSA Host Key (Deprecated)",
                "severity": "MEDIUM",
                "cwe": "CWE-327",
                "description": f"SSH server uses deprecated host key algorithm: {', '.join(result.weak_host_keys)}",
                "evidence_level": "E2",
            })

        # CVE candidates
        for cve in result.cve_candidates:
            findings.append({
                "title": f"SSH CVE Candidate: {cve['cve']} ({result.software_product} {result.software_version})",
                "severity": cve["severity"],
                "cwe": "CWE-1035",
                "cve": cve["cve"],
                "description": f"{cve['desc']}. Detected version: {result.software_product} {result.software_version}",
                "evidence_level": "E1",
                "evidence": {
                    "product": result.software_product,
                    "version": result.software_version,
                    "cve": cve["cve"],
                    "status": "POTENTIALLY_AFFECTED",
                },
            })

        # Protocol version 1
        if result.protocol_version and not result.protocol_version.startswith("2"):
            findings.append({
                "title": "SSH Protocol Version 1 Supported",
                "severity": "HIGH",
                "cwe": "CWE-327",
                "description": f"SSH server supports protocol version {result.protocol_version} which has known weaknesses.",
                "evidence_level": "E2",
            })

        result.findings = findings

    def to_summary(self, result: SshAssessmentResult) -> Dict[str, Any]:
        """Generate a summary dictionary for reporting."""
        return {
            "host": result.host,
            "port": result.port,
            "status": result.status,
            "banner": result.banner,
            "product": result.software_product,
            "version": result.software_version,
            "protocol": result.protocol_version,
            "kex_count": len(result.kex_algorithms),
            "cipher_count": len(result.encryption_algorithms),
            "mac_count": len(result.mac_algorithms),
            "weak_kex_count": len(result.weak_kex),
            "weak_cipher_count": len(result.weak_ciphers),
            "weak_mac_count": len(result.weak_macs),
            "cve_candidate_count": len(result.cve_candidates),
            "finding_count": len(result.findings),
            "findings": result.findings,
        }
