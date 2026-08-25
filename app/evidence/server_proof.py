"""Server-Level Evidence Collector & Artifact Sanitizer (V5 §21, §22, §25).

Captures, redacts, and structures proof of server-level access:
- Arbitrary file reads (/etc/passwd, .env, config.php)
- Directory listings / folder contents
- Database schemas / table lists
- Runtime configuration dumps (phpinfo, Spring Actuator)
- Environment variable exposures

Ensures customer-facing reports receive redacted proof while maintaining
cryptographic hash integrity (SHA-256) for researcher verification.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("evidence.server_proof")


class ServerProofCollector:
    """Collects and standardizes server-level proof artifacts."""

    SENSITIVE_KEY_PATTERNS = [
        r"password", r"passwd", r"secret", r"api[_-]?key", r"token",
        r"private[_-]?key", r"auth", r"jwt", r"credential", r"database_url",
    ]

    @classmethod
    def sanitize_content(cls, content: str) -> str:
        """Mask plaintext secrets in file or configuration content."""
        sanitized = content
        for pattern in cls.SENSITIVE_KEY_PATTERNS:
            # Matches key = value or key: value
            regex = re.compile(rf'({pattern}\s*[:=]\s*["\']?)([^"\'\r\n\s,]+)(["\']?)', re.IGNORECASE)
            sanitized = regex.sub(r'\1[REDACTED]\3', sanitized)
        return sanitized

    @classmethod
    def create_proof_package(
        cls,
        proof_type: str,  # file_content / db_schema / dir_listing / config_dump / code_execution
        target_host: str,
        raw_content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Build a cryptographically hashed, redacted server proof package."""
        sha256_hash = hashlib.sha256(raw_content.encode()).hexdigest()
        sanitized_content = cls.sanitize_content(raw_content)

        package = {
            "proof_id": f"proof_{sha256_hash[:12]}",
            "proof_type": proof_type,
            "target_host": target_host,
            "sha256": sha256_hash,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "content_length_bytes": len(raw_content),
            "sanitized_sample": sanitized_content[:1500],
            "metadata": metadata or {},
            "verified": True,
        }
        return package


# Module-level singleton
server_proof_collector = ServerProofCollector()
