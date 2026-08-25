"""Evidence Retention Policy Engine (V5 §47).
Enforces configurable time-to-live (TTL) across screenshots, reports,
raw scanner outputs, and sensitive artifacts:
retention:
  screenshots: 180d
  reports: 365d
  raw_scanner_output: 30d
  sensitive_artifacts: 7d
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

logger = logging.getLogger("evidence.retention")


class RetentionPolicy:
    """Configurable Evidence Lifecycle & Archival Manager (§47)."""

    DEFAULT_POLICY = {
        "screenshots_days": 180,
        "reports_days": 365,
        "raw_scanner_output_days": 30,
        "sensitive_artifacts_days": 7,
    }

    @classmethod
    def is_expired(cls, artifact_type: str, created_at: datetime, policy: Dict[str, int] = None) -> bool:
        """Check if an evidence artifact exceeds its retention TTL."""
        pol = policy or cls.DEFAULT_POLICY
        now = datetime.now(timezone.utc)
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)

        ttl_days = pol.get(f"{artifact_type}_days", 30)
        cutoff = now - timedelta(days=ttl_days)
        return created_at < cutoff
