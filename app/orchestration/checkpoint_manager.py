"""Investigation Checkpoint Manager, Pause & Resume Engine (V13 §18, §37, §38).

Supports persistent progress checkpointing:
- Saves current phase, subdomains completed, discovered endpoints, and completed modules.
- Enables non-destructive investigation PAUSE and RESUME without restarting from zero.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("orchestration.checkpoint_manager")


@dataclass
class InvestigationCheckpoint:
    scan_id: str
    tenant_id: str
    target: str
    phase: str
    subdomains_completed: int = 0
    endpoints_discovered: int = 0
    findings_count: int = 0
    completed_modules: List[str] = field(default_factory=list)
    pending_tasks: List[Dict[str, Any]] = field(default_factory=list)
    is_paused: bool = False
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "tenant_id": self.tenant_id,
            "target": self.target,
            "phase": self.phase,
            "subdomains_completed": self.subdomains_completed,
            "endpoints_discovered": self.endpoints_discovered,
            "findings_count": self.findings_count,
            "completed_modules": self.completed_modules,
            "pending_tasks_count": len(self.pending_tasks),
            "is_paused": self.is_paused,
            "timestamp": self.timestamp,
        }


class CheckpointManager:
    """Manages persistent checkpoints, pause, and resume workflows."""

    def __init__(self) -> None:
        self._checkpoints: Dict[str, InvestigationCheckpoint] = {}
        self._lock = asyncio.Lock()

    async def save_checkpoint(
        self,
        scan_id: str,
        tenant_id: str,
        target: str,
        phase: str,
        subdomains_completed: int = 0,
        endpoints_discovered: int = 0,
        findings_count: int = 0,
        completed_modules: Optional[List[str]] = None,
        pending_tasks: Optional[List[Dict[str, Any]]] = None,
    ) -> InvestigationCheckpoint:
        """Persists granular progress state."""
        async with self._lock:
            existing = self._checkpoints.get(scan_id)
            is_paused = existing.is_paused if existing else False

            checkpoint = InvestigationCheckpoint(
                scan_id=scan_id,
                tenant_id=tenant_id,
                target=target,
                phase=phase,
                subdomains_completed=subdomains_completed,
                endpoints_discovered=endpoints_discovered,
                findings_count=findings_count,
                completed_modules=completed_modules or [],
                pending_tasks=pending_tasks or [],
                is_paused=is_paused,
                timestamp=time.time(),
            )
            self._checkpoints[scan_id] = checkpoint
            return checkpoint

    async def pause_investigation(self, scan_id: str) -> bool:
        """Sets the pause flag on an investigation."""
        async with self._lock:
            chk = self._checkpoints.get(scan_id)
            if chk:
                chk.is_paused = True
                logger.info("Investigation %s PAUSED.", scan_id)
                return True
            return False

    async def resume_investigation(self, scan_id: str) -> Optional[InvestigationCheckpoint]:
        """Resumes a paused investigation from its checkpoint."""
        async with self._lock:
            chk = self._checkpoints.get(scan_id)
            if chk:
                chk.is_paused = False
                logger.info("Investigation %s RESUMED from phase: %s", scan_id, chk.phase)
                return chk
            return None

    def get_checkpoint(self, scan_id: str) -> Optional[InvestigationCheckpoint]:
        return self._checkpoints.get(scan_id)

    async def reset(self) -> None:
        """Resets all checkpoints."""
        async with self._lock:
            self._checkpoints.clear()


checkpoint_manager = CheckpointManager()
