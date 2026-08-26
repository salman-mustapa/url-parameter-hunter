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

    @classmethod
    def create_exploitation_evidence(
        cls,
        vuln_type: str,  # sqli / rce / xss / idor
        target_host: str,
        exploitation_data: Dict[str, Any],
        raw_response: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Build a structured exploitation evidence package for deep proof.

        Packages database schemas, command outputs, IDOR object data, and XSS DOM context
        into a verifiable, redacted evidence record.
        """
        # Hash the exploitation data for integrity
        data_str = json.dumps(exploitation_data, sort_keys=True, default=str)
        sha256_hash = hashlib.sha256(data_str.encode()).hexdigest()

        # Build structured evidence
        evidence: Dict[str, Any] = {
            "exploitation_proof_id": f"exploit_{sha256_hash[:12]}",
            "vulnerability_type": vuln_type,
            "target_host": target_host,
            "sha256_integrity": sha256_hash,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "verified": True,
        }

        if vuln_type == "sqli":
            evidence["database_exploitation"] = {
                "database_name": exploitation_data.get("database_name", ""),
                "database_user": exploitation_data.get("database_user", ""),
                "database_version": exploitation_data.get("database_version", ""),
                "tables_extracted": exploitation_data.get("tables", []),
                "columns_extracted": exploitation_data.get("columns", {}),
                "row_counts": exploitation_data.get("row_counts", {}),
                "column_count": exploitation_data.get("column_count", 0),
            }

        elif vuln_type == "rce":
            cmd_outputs = exploitation_data.get("command_outputs", {})
            evidence["system_exploitation"] = {
                "current_user": exploitation_data.get("current_user", ""),
                "hostname": exploitation_data.get("hostname", ""),
                "kernel_info": exploitation_data.get("kernel_info", ""),
                "uid": exploitation_data.get("uid"),
                "privilege_level": exploitation_data.get("privilege_level", ""),
                "privileged_groups": exploitation_data.get("privileged_groups", []),
                "passwd_entries": exploitation_data.get("passwd_entries", 0),
                "real_users": exploitation_data.get("real_users", []),
                "commands_executed": exploitation_data.get("commands_executed", 0),
            }
            # Include sanitized command outputs
            sanitized_outputs = {}
            for key, output in cmd_outputs.items():
                sanitized_outputs[key] = cls.sanitize_content(str(output))[:500]
            evidence["system_exploitation"]["command_outputs_sanitized"] = sanitized_outputs

        elif vuln_type == "xss":
            evidence["xss_exploitation"] = {
                "payload_intact_in_dom": exploitation_data.get("payload_intact_in_dom", False),
                "dom_context_sample": exploitation_data.get("dom_context_sample", "")[:300],
                "session_hijack_risk": exploitation_data.get("session_hijack_risk", ""),
                "verified_payloads_count": exploitation_data.get("verified_payloads_count", 0),
                "csp_analysis": exploitation_data.get("csp_analysis", {}),
                "cookie_analysis": exploitation_data.get("cookie_analysis", {}),
            }

        elif vuln_type == "idor":
            evidence["idor_exploitation"] = {
                "total_accessible": exploitation_data.get("total_accessible", 0),
                "unique_objects": exploitation_data.get("unique_objects", 0),
                "sensitive_fields_exposed": exploitation_data.get("sensitive_fields_exposed", []),
                "authorization_bypass_confirmed": exploitation_data.get("authorization_bypass_confirmed", False),
                "accessible_objects": exploitation_data.get("accessible_objects", [])[:5],
            }

        # Include raw response sample (sanitized)
        if raw_response:
            evidence["raw_response_sample"] = cls.sanitize_content(raw_response)[:1000]

        return evidence


# Module-level singleton
server_proof_collector = ServerProofCollector()

