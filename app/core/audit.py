"""Comprehensive Audit Trail Subsystem (V8 §49).

Logs:
- who (operator/system)
- what (action/test)
- when (ISO timestamp)
- target (host/url)
- scope (scope_id / root_domain)
- action
- authorization (reference / authorization_id)
- tool & tool version
- AI decision id & policy result
- result (SUCCESS, BLOCKED, FAILED, APPROVED)
- evidence id / hash
- cleanup status

Especially tracks:
- Credential & hash assessment attempts
- Controlled validation executions
- High-risk L4 approvals
- Lab simulations
- Report generation & redactions
- Retest executions
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import AuditLog

logger = logging.getLogger("core.audit")


class AuditTrailManager:
    """Structured audit trail recorder (V8 §49)."""

    @classmethod
    async def record_audit_event(
        cls,
        db: AsyncSession,
        *,
        actor: str,
        action: str,
        target: Optional[str] = None,
        scope: Optional[str] = None,
        scan_id: Optional[str] = None,
        authorization_ref: Optional[str] = None,
        tool_name: Optional[str] = None,
        tool_version: Optional[str] = "v8.0.0",
        ai_decision_id: Optional[str] = None,
        result_status: str = "SUCCESS",
        evidence_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditLog:
        """Records a comprehensive structured audit event in the database."""
        entry = AuditLog(
            actor=actor,
            action=action,
            target=target,
            scope=scope,
            scan_id=scan_id or "global",
            authorization_ref=authorization_ref,
            tool_name=tool_name,
            tool_version=tool_version,
            ai_decision_id=ai_decision_id,
            result_status=result_status,
            evidence_id=evidence_id,
            details=details or {},
        )
        try:
            db.add(entry)
            await db.commit()
            logger.info("AUDIT LOG: %s on %s by %s (Status: %s)", action, target, actor, result_status)
        except Exception as exc:
            logger.error("Failed to commit audit entry: %s", exc)

        return entry


audit_trail_manager = AuditTrailManager()
