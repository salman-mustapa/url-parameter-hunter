from __future__ import annotations

import re
from typing import Any


def sanitize_text(val: Any) -> Any:
    """
    Recursively removes null bytes (\\x00) and dangerous non-printable control characters
    to prevent PostgreSQL CharacterNotInRepertoireError and JSON parsing issues.
    """
    if isinstance(val, str):
        # Remove null bytes and non-printable control characters except standard whitespace
        cleaned = val.replace("\x00", "")
        # Filter unprintable chars
        return "".join(ch for ch in cleaned if ch.isprintable() or ch in "\n\r\t")
    elif isinstance(val, dict):
        return {sanitize_text(k): sanitize_text(v) for k, v in val.items()}
    elif isinstance(val, (list, tuple, set)):
        return [sanitize_text(x) for x in val]
    return val


def clean_banner(raw_bytes: bytes) -> str | None:
    """Decodes and cleans raw network banners for safe DB storage."""
    if not raw_bytes:
        return None
    try:
        decoded = raw_bytes.decode("utf-8", errors="ignore")
    except Exception:
        decoded = raw_bytes.decode("latin-1", errors="ignore")
    
    # Strip null bytes and non-printable characters
    cleaned = "".join(ch for ch in decoded if ch.isprintable() or ch in " \t")
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned[:150] if cleaned else None
