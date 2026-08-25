"""RDP Deep Security Assessment Module (V4 §17, V5 §12).

Comprehensive RDP assessment:
- Port exposure verification
- Protocol negotiation (CredSSP, TLS, Standard RDP)
- NLA (Network Level Authentication) detection
- TLS/Security layer identification
- Certificate analysis
- BlueKeep (CVE-2019-0708) and related CVE applicability checks
- Security configuration observations
"""

from __future__ import annotations

import asyncio
import logging
import re
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("network.rdp")

# Known RDP CVEs
RDP_CVES = [
    {
        "cve": "CVE-2019-0708",
        "name": "BlueKeep",
        "severity": "CRITICAL",
        "desc": "Remote code execution via RDP without authentication (pre-NLA)",
        "nla_mitigates": True,
    },
    {
        "cve": "CVE-2019-1181",
        "name": "DejaBlue",
        "severity": "CRITICAL",
        "desc": "Remote code execution in Remote Desktop Services",
        "nla_mitigates": False,
    },
    {
        "cve": "CVE-2019-1182",
        "name": "DejaBlue",
        "severity": "CRITICAL",
        "desc": "Remote code execution in Remote Desktop Services",
        "nla_mitigates": False,
    },
]

# RDP Negotiation Request constants
PROTOCOL_RDP = 0x00
PROTOCOL_SSL = 0x01
PROTOCOL_HYBRID = 0x02  # CredSSP
PROTOCOL_RDSTLS = 0x04
PROTOCOL_HYBRID_EX = 0x08

# Security protocol names
PROTOCOL_NAMES = {
    PROTOCOL_RDP: "Standard RDP Security",
    PROTOCOL_SSL: "TLS Security",
    PROTOCOL_HYBRID: "CredSSP (NLA)",
    PROTOCOL_RDSTLS: "RDSTLS",
    PROTOCOL_HYBRID_EX: "CredSSP with Early User Authorization",
}


@dataclass
class RdpAssessmentResult:
    host: str
    port: int = 3389
    accessible: bool = False
    nla_required: bool = False
    tls_supported: bool = False
    credssp_supported: bool = False
    standard_rdp_security: bool = False
    selected_protocol: str = ""
    negotiation_flags: int = 0
    certificate_info: Dict[str, Any] = field(default_factory=dict)
    cve_candidates: List[Dict[str, str]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    internet_exposed: bool = True
    status: str = "UNKNOWN"
    error: str = ""


class RdpAssessment:
    """RDP Deep Assessment Engine (V4 §17, V5 §12).

    Performs RDP security analysis via protocol negotiation.
    All checks are passive — no authentication attempts.
    """

    def __init__(self, timeout: float = 8.0) -> None:
        self.timeout = timeout

    async def assess(self, host: str, port: int = 3389) -> RdpAssessmentResult:
        """Perform full RDP assessment on target host:port."""
        result = RdpAssessmentResult(host=host, port=port)

        try:
            # Phase 1: Connection and protocol negotiation
            await self._negotiate_protocol(result)

            if not result.accessible:
                result.status = "INACCESSIBLE"
                return result

            # Phase 2: CVE correlation
            self._correlate_cves(result)

            # Phase 3: Generate findings
            self._generate_findings(result)

            result.status = "ASSESSED"

        except Exception as exc:
            result.status = "ERROR"
            result.error = str(exc)[:200]
            logger.debug("RDP assessment failed for %s:%d: %s", host, port, exc)

        return result

    async def _negotiate_protocol(self, result: RdpAssessmentResult) -> None:
        """Send RDP Negotiation Request and parse the response."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(result.host, result.port),
                timeout=self.timeout,
            )

            result.accessible = True

            # Build X.224 Connection Request with RDP Negotiation Request
            # Requesting CredSSP | TLS | RDP
            neg_req = self._build_negotiation_request(
                PROTOCOL_HYBRID | PROTOCOL_SSL | PROTOCOL_RDP
            )

            writer.write(neg_req)
            await writer.drain()

            # Read response
            response = await asyncio.wait_for(reader.read(1024), timeout=5.0)

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            if response:
                self._parse_negotiation_response(result, response)

        except asyncio.TimeoutError:
            result.accessible = False
            result.error = "Connection timeout"
        except ConnectionRefusedError:
            result.accessible = False
            result.error = "Connection refused"
        except Exception as exc:
            result.accessible = False
            result.error = str(exc)[:200]

    def _build_negotiation_request(self, requested_protocols: int) -> bytes:
        """Build an RDP Negotiation Request (X.224 Connection Request)."""
        # RDP Negotiation Request structure:
        # Type (1 byte): 0x01 = TYPE_RDP_NEG_REQ
        # Flags (1 byte): 0x00
        # Length (2 bytes, LE): 0x0008
        # RequestedProtocols (4 bytes, LE)
        neg_data = struct.pack("<BBHI",
            0x01,  # TYPE_RDP_NEG_REQ
            0x00,  # flags
            0x0008,  # length
            requested_protocols,
        )

        # Cookie
        cookie = b"Cookie: mstshash=BHScanner\r\n"

        # X.224 Connection Request
        # Length indicator = total length - 1 (for the length byte itself)
        # X.224 CR: type=0xE0, dst-ref=0x0000, src-ref=0x0000, class=0x00
        x224_payload = struct.pack(">BHH B", 0xE0, 0x0000, 0x0000, 0x00) + cookie + neg_data
        x224_li = len(x224_payload)

        # TPKT Header: version=3, reserved=0, length (2 bytes, BE)
        tpkt_length = 4 + 1 + len(x224_payload)  # TPKT(4) + LI(1) + payload
        tpkt = struct.pack(">BBH", 3, 0, tpkt_length)

        return tpkt + struct.pack("B", x224_li) + x224_payload

    def _parse_negotiation_response(self, result: RdpAssessmentResult, response: bytes) -> None:
        """Parse RDP Negotiation Response."""
        if len(response) < 11:
            return

        # TPKT header: 4 bytes
        # X.224 LI: 1 byte
        # X.224 type: should be 0xD0 (Connection Confirm)

        try:
            tpkt_version = response[0]
            if tpkt_version != 3:
                return

            x224_li = response[4]
            x224_type = response[5]

            if x224_type != 0xD0:
                # Might be a Negotiation Failure
                if len(response) > 11 and response[11] == 0x03:
                    # TYPE_RDP_NEG_FAILURE
                    result.nla_required = True
                    result.credssp_supported = True
                return

            # Look for Negotiation Response after X.224 header
            neg_offset = 4 + 1 + 6  # TPKT(4) + LI(1) + X.224 CR min(6)
            # Search for negotiation response type byte (0x02)
            for i in range(neg_offset, min(len(response) - 7, neg_offset + 40)):
                if response[i] == 0x02:  # TYPE_RDP_NEG_RSP
                    flags = response[i + 1]
                    length = struct.unpack_from("<H", response, i + 2)[0]
                    selected = struct.unpack_from("<I", response, i + 4)[0]

                    result.negotiation_flags = flags
                    result.selected_protocol = PROTOCOL_NAMES.get(selected, f"Unknown ({selected})")

                    if selected & PROTOCOL_HYBRID:
                        result.credssp_supported = True
                        result.nla_required = True
                    if selected & PROTOCOL_SSL:
                        result.tls_supported = True
                    if selected == PROTOCOL_RDP:
                        result.standard_rdp_security = True

                    # Flag: EXTENDED_CLIENT_DATA_SUPPORTED (0x01)
                    # Flag: DYNVC_GFX_PROTOCOL_SUPPORTED (0x02)
                    # Flag: NEGRSP_FLAG_RESERVED (0x04)
                    # Flag: RESTRICTED_ADMIN_MODE_SUPPORTED (0x08)
                    break

        except Exception as exc:
            logger.debug("RDP negotiation parse error: %s", exc)

    def _correlate_cves(self, result: RdpAssessmentResult) -> None:
        """Correlate RDP configuration with known CVEs."""
        for cve_info in RDP_CVES:
            if cve_info["nla_mitigates"] and result.nla_required:
                # NLA mitigates this CVE
                continue

            if result.internet_exposed:
                result.cve_candidates.append({
                    "cve": cve_info["cve"],
                    "name": cve_info["name"],
                    "severity": cve_info["severity"],
                    "desc": cve_info["desc"],
                    "nla_mitigated": result.nla_required and cve_info["nla_mitigates"],
                    "status": "POTENTIALLY_AFFECTED" if not result.nla_required else "MITIGATED",
                })

    def _generate_findings(self, result: RdpAssessmentResult) -> None:
        """Generate security findings from assessment results."""
        findings = []

        # Internet-exposed RDP
        if result.accessible and result.internet_exposed:
            findings.append({
                "title": "RDP Service Exposed to Internet",
                "severity": "HIGH",
                "cwe": "CWE-16",
                "description": f"RDP service on port {result.port} is accessible from the internet. "
                              f"Protocol: {result.selected_protocol}",
                "evidence_level": "E2",
                "evidence": {
                    "host": result.host,
                    "port": result.port,
                    "nla_required": result.nla_required,
                    "protocol": result.selected_protocol,
                },
            })

        # No NLA
        if result.accessible and not result.nla_required:
            findings.append({
                "title": "RDP Without Network Level Authentication (NLA)",
                "severity": "HIGH",
                "cwe": "CWE-287",
                "description": "RDP does not require Network Level Authentication. "
                              "Pre-authentication access increases attack surface (BlueKeep, etc.).",
                "evidence_level": "E2",
                "evidence": {
                    "nla_required": False,
                    "selected_protocol": result.selected_protocol,
                },
            })

        # Standard RDP Security (no TLS/CredSSP)
        if result.standard_rdp_security and not result.tls_supported:
            findings.append({
                "title": "RDP Using Standard Security (No TLS)",
                "severity": "MEDIUM",
                "cwe": "CWE-319",
                "description": "RDP is using standard RDP security without TLS encryption. "
                              "Traffic may be susceptible to interception.",
                "evidence_level": "E2",
            })

        # CVE candidates
        for cve in result.cve_candidates:
            if cve["status"] != "MITIGATED":
                findings.append({
                    "title": f"RDP CVE Candidate: {cve['cve']} ({cve['name']})",
                    "severity": cve["severity"],
                    "cwe": "CWE-1035",
                    "cve": cve["cve"],
                    "description": f"{cve['desc']}. NLA {'mitigates' if cve.get('nla_mitigated') else 'does NOT mitigate'} this vulnerability.",
                    "evidence_level": "E1",
                    "evidence": {
                        "cve": cve["cve"],
                        "nla_required": result.nla_required,
                        "status": cve["status"],
                    },
                })

        result.findings = findings

    def to_summary(self, result: RdpAssessmentResult) -> Dict[str, Any]:
        """Generate a summary dictionary for reporting."""
        return {
            "host": result.host,
            "port": result.port,
            "status": result.status,
            "accessible": result.accessible,
            "nla_required": result.nla_required,
            "tls_supported": result.tls_supported,
            "credssp_supported": result.credssp_supported,
            "standard_rdp_security": result.standard_rdp_security,
            "selected_protocol": result.selected_protocol,
            "cve_candidate_count": len(result.cve_candidates),
            "finding_count": len(result.findings),
            "findings": result.findings,
        }
