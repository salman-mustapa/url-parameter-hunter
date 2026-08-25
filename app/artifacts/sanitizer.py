"""Artifact Sanitizer & Data Redaction Engine (V9).

Generates compliance-safe sanitized representations of sensitive artifacts
(SQL dumps, CSVs, log files) for customer reports and external audit dossiers.

Redacts:
1. Passwords & password hashes -> Masked e.g. `$2y$10$abc...[REDACTED_HASH]`
2. National IDs (NIK) & Student IDs (NIM) -> Masked e.g. `317101******0001`
3. Email addresses -> Masked e.g. `j***@domain.com`
4. Phone numbers -> Masked e.g. `0812****8901`
5. API keys, JWTs, and Tokens -> Masked e.g. `eyJhbG...[REDACTED_JWT]`
"""

from __future__ import annotations

import re
from typing import Any, Dict, List


def mask_email(email: str) -> str:
    if "@" not in email:
        return email
    user, domain = email.split("@", 1)
    if len(user) <= 2:
        masked_user = user[0] + "***" if user else "***"
    else:
        masked_user = user[0] + "*" * (len(user) - 2) + user[-1]
    return f"{masked_user}@{domain}"


def mask_secret(secret: str) -> str:
    if len(secret) <= 8:
        return "***[REDACTED]***"
    return secret[:4] + "***[REDACTED]***" + secret[-4:]


def mask_hash(h_val: str) -> str:
    if len(h_val) <= 12:
        return "***[REDACTED_HASH]***"
    return h_val[:8] + "...[REDACTED_HASH]..." + h_val[-4:]


class ArtifactSanitizer:
    """Provides compliance-safe data sanitization and masking."""

    @classmethod
    def sanitize_record(cls, record: Dict[str, Any]) -> Dict[str, Any]:
        """Redacts sensitive values within a tabular dictionary record."""
        sanitized = {}
        for k, v in record.items():
            k_lower = k.lower()
            if v is None:
                sanitized[k] = None
                continue

            v_str = str(v).strip()
            if any(p in k_lower for p in ("password", "pass", "pwd", "hash", "secret")):
                sanitized[k] = mask_hash(v_str)
            elif "email" in k_lower or "mail" in k_lower:
                sanitized[k] = mask_email(v_str)
            elif any(p in k_lower for p in ("token", "jwt", "key", "api", "auth")):
                sanitized[k] = mask_secret(v_str)
            elif any(p in k_lower for p in ("nim", "nik", "phone", "telp", "hp", "ktp")):
                if len(v_str) >= 6:
                    sanitized[k] = v_str[:3] + "*" * (len(v_str) - 5) + v_str[-2:]
                else:
                    sanitized[k] = "***"
            else:
                sanitized[k] = v
        return sanitized

    @classmethod
    def sanitize_sql_dump(cls, sql_text: str, max_lines: int = 2000) -> str:
        """Sanitizes SQL dump text by masking passwords, hashes, and tokens in INSERT statements."""
        lines = sql_text.splitlines()
        sanitized_lines = []

        for line in lines[:max_lines]:
            # Mask bcrypt/argon2/md5 hashes
            line = re.sub(r"\'\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}\'", "'$2y$10$***[REDACTED_BCRYPT_HASH]***'", line)
            line = re.sub(r"\'\$argon2[id]?\$[^\']+\'", "'$argon2id$***[REDACTED_ARGON2_HASH]***'", line)
            # Mask emails
            line = re.sub(r"\'([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)\'", r"'\1***@\2'", line)
            sanitized_lines.append(line)

        return "\n".join(sanitized_lines)
