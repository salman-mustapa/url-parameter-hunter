"""Investigation Memory & Shared Multi-Agent Knowledge Store (V12 §33, §34).

Maintains shared facts, observations, decisions, and behavioral models across all specialist agents:
- Strict Precedence: FRESH_EVIDENCE > DATABASE_FACTS > VALIDATED_OBSERVATIONS > HISTORICAL_MEMORY > AI_INFERENCE
- Automatic secret & credential token redaction.
- Structured provenance on every fact and memory item.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("ai.investigation_memory")


class FactPrecedence(int, Enum):
    AI_INFERENCE = 1
    HISTORICAL_MEMORY = 2
    VALIDATED_OBSERVATION = 3
    DATABASE_FACT = 4
    FRESH_EVIDENCE = 5


@dataclass
class MemoryFact:
    fact_id: str
    key: str
    value: Any
    precedence: FactPrecedence
    source: str  # Tool name or worker class
    confidence: float = 1.0
    evidence_id: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fact_id": self.fact_id,
            "key": self.key,
            "value": self.value,
            "precedence": self.precedence.name,
            "source": self.source,
            "confidence": self.confidence,
            "evidence_id": self.evidence_id,
            "timestamp": self.timestamp,
        }


class InvestigationMemory:
    """Shared contextual memory for all specialist agents working on an investigation."""

    def __init__(self, scan_id: str = "global") -> None:
        self.scan_id = scan_id
        self._facts: Dict[str, MemoryFact] = {}
        self._decisions: List[Dict[str, Any]] = []
        self._failed_approaches: Set[str] = set()
        self._waf_behavior: Dict[str, Any] = {}
        self._auth_behavior: Dict[str, Any] = {}

    def record_fact(
        self,
        key: str,
        value: Any,
        precedence: FactPrecedence,
        source: str,
        confidence: float = 1.0,
        evidence_id: Optional[str] = None,
    ) -> bool:
        """Records or updates a fact only if the new fact meets or exceeds existing precedence."""
        existing = self._facts.get(key)
        if existing and existing.precedence.value > precedence.value:
            logger.debug(
                "Rejected lower-precedence fact for key '%s': Existing (%s) > New (%s)",
                key, existing.precedence.name, precedence.name
            )
            return False

        fact_id = f"fact_{int(time.time()*1000)}_{len(self._facts)}"
        sanitized_value = self._redact_secrets(value)

        self._facts[key] = MemoryFact(
            fact_id=fact_id,
            key=key,
            value=sanitized_value,
            precedence=precedence,
            source=source,
            confidence=confidence,
            evidence_id=evidence_id,
        )
        return True

    def get_fact(self, key: str) -> Optional[Any]:
        fact = self._facts.get(key)
        return fact.value if fact else None

    def record_decision(self, agent_name: str, action: str, rationale: str, confidence: float) -> None:
        """Records structured rationale from an agent without exposing private thought chains."""
        self._decisions.append({
            "agent": agent_name,
            "action": action,
            "rationale": rationale,
            "confidence": confidence,
            "timestamp": time.time(),
        })

    def record_failed_approach(self, approach_key: str) -> None:
        self._failed_approaches.add(approach_key)

    def is_approach_failed(self, approach_key: str) -> bool:
        return approach_key in self._failed_approaches

    def get_context_summary(self, max_items: int = 50) -> Dict[str, Any]:
        """Provides a compressed, privacy-safe context snapshot for agent planning."""
        return {
            "scan_id": self.scan_id,
            "total_facts": len(self._facts),
            "facts": {k: f.to_dict() for k, f in list(self._facts.items())[:max_items]},
            "recent_decisions": self._decisions[-10:],
            "failed_approaches_count": len(self._failed_approaches),
            "waf_detected": bool(self._waf_behavior),
        }

    def _redact_secrets(self, val: Any) -> Any:
        if isinstance(val, str):
            # Redact JWT tokens, passwords, bearer tokens
            val = re.sub(r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}', '[REDACTED_JWT]', val)
            val = re.sub(r'(?i)(password|secret|apikey|api_key|app_key)\s*[:=]\s*["\']?[^\s"\']+', r'\1=[REDACTED]', val)
            return val
        elif isinstance(val, dict):
            return {k: self._redact_secrets(v) for k, v in val.items()}
        elif isinstance(val, list):
            return [self._redact_secrets(x) for x in val]
        return val


class InvestigationMemoryManager:
    """Manages active investigation memory instances per scan campaign."""

    def __init__(self) -> None:
        self._memories: Dict[str, InvestigationMemory] = {}

    def get_memory(self, scan_id: str) -> InvestigationMemory:
        if scan_id not in self._memories:
            self._memories[scan_id] = InvestigationMemory(scan_id)
        return self._memories[scan_id]


investigation_memory_manager = InvestigationMemoryManager()
