"""Secret & Information Disclosure Detection Engine (§85).

Detects API keys, tokens, credentials, private keys, cloud secrets,
and sensitive configuration indicators. Auto-redacts findings.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from app.reporting.redaction import redact

# High-precision regular expressions for common secrets & credentials
SECRET_PATTERNS = [
    {
        "id": "sec_aws_key",
        "name": "AWS Access Key ID",
        "pattern": re.compile(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
        "severity": "HIGH",
        "cwe": "CWE-798",
        "description": "AWS Access Key ID terdeteksi dalam respons publik.",
    },
    {
        "id": "sec_jwt_token",
        "name": "JSON Web Token (JWT)",
        "pattern": re.compile(r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*"),
        "severity": "MEDIUM",
        "cwe": "CWE-200",
        "description": "JWT Token terdeteksi dalam respons/skrip, berpotensi mengekspos klaim sesi atau data pengguna.",
    },
    {
        "id": "sec_generic_api_key",
        "name": "Generic API Key / Secret Token",
        "pattern": re.compile(r"""(?i)(?:api_key|apikey|secret_key|api_secret|auth_token|access_token|private_key)\s*[:=]\s*['"]([0-9a-zA-Z_\-]{16,64})['"]"""),
        "severity": "HIGH",
        "cwe": "CWE-798",
        "description": "Hardcoded API Key atau token autentikasi terdeteksi dalam konten respons.",
    },
    {
        "id": "sec_github_token",
        "name": "GitHub Personal Access Token",
        "pattern": re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"),
        "severity": "CRITICAL",
        "cwe": "CWE-798",
        "description": "GitHub Access Token terdeteksi, memungkinkan akses tidak sah ke repository kode sumber.",
    },
    {
        "id": "sec_slack_webhook",
        "name": "Slack Incoming Webhook URL",
        "pattern": re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}"),
        "severity": "HIGH",
        "cwe": "CWE-200",
        "description": "Slack Webhook URL terdeteksi, memungkinkan pengiriman pesan palsu atau penyusupan alur notifikasi.",
    },
    {
        "id": "sec_google_api_key",
        "name": "Google API Key",
        "pattern": re.compile(r"AIza[0-9A-Za-z-_]{35}"),
        "severity": "MEDIUM",
        "cwe": "CWE-200",
        "description": "Google API Key terdeteksi. Disarankan membatasi cakupan referer dan API yang diizinkan.",
    },
    {
        "id": "sec_rsa_private_key",
        "name": "RSA / OpenSSH Private Key Header",
        "pattern": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        "severity": "CRITICAL",
        "cwe": "CWE-312",
        "description": "Private Key kriptografi terdeteksi terekspos secara publik.",
    },
]


class SecretScanner:
    """Secret detection scanner with auto-redaction (§85)."""

    @classmethod
    def scan_text(cls, text: str, source_url: str = "") -> List[Dict[str, Any]]:
        findings = []
        if not text:
            return findings

        for rule in SECRET_PATTERNS:
            matches = rule["pattern"].findall(text)
            if matches:
                # Deduplicate matches
                unique_matches = list(set(matches))[:5]
                for raw_match in unique_matches:
                    match_str = raw_match if isinstance(raw_match, str) else raw_match[0]
                    # Redact the secret for evidence
                    safe_secret = redact(match_str)
                    findings.append({
                        "id": rule["id"],
                        "name": rule["name"],
                        "severity": rule["severity"],
                        "cwe": rule["cwe"],
                        "description": rule["description"],
                        "source_url": source_url,
                        "match_redacted": safe_secret,
                    })

        return findings


secret_scanner = SecretScanner()
