from __future__ import annotations

import re
from typing import Any, Dict, List, Union


class RedactionEngine:
    """Report Redaction Engine (§53).
    Redacts credentials, cookies, tokens, API keys, and sensitive response data from client-facing reports.
    """

    REDACTION_RULES = [
        (re.compile(r'(?i)((?:redis|rediss|postgresql(?:\+asyncpg)?|mysql)://)[^/@\s]+:[^/@\s]+@'), r'\1[REDACTED]@'),
        (re.compile(r'(?i)(\b(?:[a-z0-9]+_)*(?:token|secret|api_key)\s*[=:]\s*)[^\s,;\"\']+'), r'\1[REDACTED]'),
        (re.compile(r'(?i)([?&](?:token|access_token|refresh_token|api_key|secret|password|session_id)=)[^&#\s]+'), r'\1[REDACTED]'),
        (re.compile(r'(?i)(https?://)[^/@\s]+:[^/@\s]+@'), r'\1[REDACTED]@'),
        (re.compile(r'((?:authorization|cookie|set-cookie)\s*:\s*)[^\r\n]+', re.I), r'\1[REDACTED]'),
        (re.compile(r'("(?:password|passwd|pwd|token|access_token|api_key|secret|plaintext)"\s*:\s*)"[^"]*"', re.I), r'\1"[REDACTED]"'),
        (re.compile(r'(password|passwd|pwd)\s*[:=]\s*["\']?([^"\'\s&]+)', re.I), r"\1=[REDACTED]"),
        (re.compile(r'(authorization:\s*bearer\s+)([a-zA-Z0-9_\-\.]+)', re.I), r"\1[REDACTED_JWT]"),
        (re.compile(r'(set-cookie:\s*[^=]+=)([^;\s]+)', re.I), r"\1[REDACTED_COOKIE]"),
        (re.compile(r'(api_?key|secret_?key)\s*[:=]\s*["\']?([^"\'\s&]+)', re.I), r"\1=[REDACTED]"),
        (re.compile(r'(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b)', re.I), r"[REDACTED_EMAIL]"),
    ]

    @classmethod
    def redact_text(cls, text: str) -> str:
        if not text:
            return ""
        redacted = text
        for pattern, repl in cls.REDACTION_RULES:
            redacted = pattern.sub(repl, redacted)
        return redacted

    @classmethod
    def redact_dict(cls, data: Union[Dict, List, str, Any]) -> Any:
        if isinstance(data, str):
            return cls.redact_text(data)
        elif isinstance(data, dict):
            sensitive = {"password", "passwd", "pwd", "authorization", "cookie", "set_cookie",
                         "token", "access_token", "refresh_token", "api_key", "apikey", "secret",
                         "secret_key", "private_key", "plaintext", "session_id", "cookies",
                         "auth_token", "csrf_tokens", "session", "client_secret", "x_api_key",
                         "x_auth_token", "x_csrf_token", "x_lab_receiver"}
            return {k: "[REDACTED]" if str(k).lower().replace("-", "_") in sensitive else cls.redact_dict(v)
                    for k, v in data.items()}
        elif isinstance(data, (list, tuple)):
            return [cls.redact_dict(item) for item in data]
        return data


def redact(text: str) -> str:
    """Convenience functional helper for text redaction."""
    return RedactionEngine.redact_text(text)
