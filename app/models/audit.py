"""Structured Audit Trail Model & Logger (V5 §48).

Tracks every critical action performed by the platform:
- Active validation probe execution
- High-risk module approval / execution
- Credential & authentication testing attempts
- Report generation and export
- Retest execution and status modifications
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import DateTime, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.models import AuditLog

logger = logging.getLogger("core.audit")


class AuditLogger:
    """Helper to record structured audit events."""

    @classmethod
    async def log(
        cls,
        db,
        action: str,
        target: str,
        operator: str = "system",
        scan_id: Optional[str] = None,
        authorization_id: Optional[str] = None,
        result_status: str = "SUCCESS",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        try:
            entry = AuditLog(
                operator=operator,
                action=action,
                target=target,
                scan_id=scan_id,
                authorization_id=authorization_id,
                result_status=result_status,
                details=details or {},
            )
            db.add(entry)
            await db.flush()
        except Exception as exc:
            logger.debug("Audit log recording error: %s", exc)


# Module-level helper
audit_logger = AuditLogger()
