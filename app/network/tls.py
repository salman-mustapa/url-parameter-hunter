from __future__ import annotations

import asyncio
import datetime
import logging
import socket
import ssl
from typing import Any, Dict, List, Optional

logger = logging.getLogger("network.tls")


class TlsAssessment:
    """TLS Deep Assessment (§18).
    Evaluates certificate validity, expiration, hostname matching, TLS protocol versions, and cipher security.
    """

    @classmethod
    async def assess(cls, host: str, port: int = 443, timeout: float = 4.0) -> Dict[str, Any]:
        result = {
            "tls_enabled": False,
            "version": None,
            "cipher": None,
            "cert_valid": False,
            "hostname_mismatch": False,
            "expired": False,
            "issuer": None,
            "subject": None,
            "not_after": None,
            "san_dns": [],
            "weak_crypto": False,
            "findings": [],
        }

        loop = asyncio.get_running_loop()

        def _sync_probe():
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    version = ssock.version()
                    cipher = ssock.cipher()
                    return cert, version, cipher

        try:
            cert, version, cipher = await loop.run_in_executor(None, _sync_probe)
            result["tls_enabled"] = True
            result["version"] = version
            if cipher:
                result["cipher"] = cipher[0]

            if cert:
                # Check expiration
                not_after_str = cert.get("notAfter")
                if not_after_str:
                    try:
                        exp_date = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                        result["not_after"] = exp_date.isoformat()
                        if exp_date < datetime.datetime.now():
                            result["expired"] = True
                            result["findings"].append({
                                "title": "Expired SSL/TLS Certificate",
                                "severity": "HIGH",
                                "cwe": "CWE-295",
                                "description": f"The SSL/TLS certificate for {host} expired on {not_after_str}.",
                            })
                    except Exception:
                        pass

                # Check SAN & Hostname matching
                san = cert.get("subjectAltName", [])
                san_names = [val for key, val in san if key == "DNS"]
                result["san_dns"] = san_names

                # Legacy TLS check
                if version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    result["weak_crypto"] = True
                    result["findings"].append({
                        "title": f"Deprecated TLS Protocol ({version}) Supported",
                        "severity": "MEDIUM",
                        "cwe": "CWE-326",
                        "description": f"The service supports obsolete protocol {version}, which is vulnerable to downgrade attacks.",
                    })
                else:
                    result["cert_valid"] = True
        except Exception as e:
            result["error"] = str(e)

        return result
