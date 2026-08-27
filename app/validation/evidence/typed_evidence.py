"""Typed Evidence Schema & Verification Models (V10 Evidence-Driven Validation Architecture).

Enforces strictly structured, typed, cryptographic evidence packages for all security findings.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class EvidenceType(str, Enum):
    HTTP_REQUEST = "HTTP_REQUEST"
    HTTP_RESPONSE = "HTTP_RESPONSE"
    REQUEST_DIFF = "REQUEST_DIFF"
    RESPONSE_DIFF = "RESPONSE_DIFF"
    TIMING = "TIMING"
    DNS = "DNS"
    TLS = "TLS"
    TCP = "TCP"
    AUTH_STATE = "AUTH_STATE"
    SESSION_STATE = "SESSION_STATE"
    IDENTITY_CONTEXT = "IDENTITY_CONTEXT"
    RESOURCE_ACCESS = "RESOURCE_ACCESS"
    DATABASE_ERROR = "DATABASE_ERROR"
    REFLECTION = "REFLECTION"
    OUT_OF_BAND = "OUT_OF_BAND"
    PROCESS_BEHAVIOR = "PROCESS_BEHAVIOR"
    FILE_CHANGE = "FILE_CHANGE"
    COMMAND_EXECUTION = "COMMAND_EXECUTION"
    NETWORK_BEHAVIOR = "NETWORK_BEHAVIOR"
    CONFIGURATION = "CONFIGURATION"
    SOURCE_CODE = "SOURCE_CODE"
    SCREENSHOT = "SCREENSHOT"
    LOG = "LOG"


@dataclass
class TypedEvidenceItem:
    """Individual typed technical evidence unit."""
    evidence_type: EvidenceType
    title: str
    description: str
    data: Dict[str, Any]
    is_primary_proof: bool = False
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_type": self.evidence_type.value if isinstance(self.evidence_type, EvidenceType) else str(self.evidence_type),
            "title": self.title,
            "description": self.description,
            "data": self.data,
            "is_primary_proof": self.is_primary_proof,
            "timestamp": self.timestamp,
        }


@dataclass
class DifferentialObservation:
    """Standardized Differential Testing Record (Baseline -> Control -> Test -> Compare)."""
    baseline_request: Dict[str, Any]
    baseline_response: Dict[str, Any]
    control_request: Optional[Dict[str, Any]] = None
    control_response: Optional[Dict[str, Any]] = None
    test_request: Dict[str, Any] = field(default_factory=dict)
    test_response: Dict[str, Any] = field(default_factory=dict)
    differences: List[str] = field(default_factory=list)
    significance_score: float = 0.0  # 0.0 - 1.0
    behavioral_anomaly_confirmed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TypedEvidencePackage:
    """Cryptographically structured evidence container meeting audit & bug bounty standards."""
    finding_id: str
    vulnerability_type: str
    target_url: str
    contract_id: str
    items: List[TypedEvidenceItem] = field(default_factory=list)
    differential: Optional[DifferentialObservation] = None
    reproduction_command: Optional[str] = None
    reproduction_steps: List[str] = field(default_factory=list)
    confidence_score: int = 0
    validation_status: str = "VALIDATED"
    sha256_fingerprint: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def compute_fingerprint(self) -> str:
        """Computes deterministic SHA-256 fingerprint over all technical evidence."""
        raw_payload = json.dumps(
            {
                "finding_id": self.finding_id,
                "vulnerability_type": self.vulnerability_type,
                "target_url": self.target_url,
                "contract_id": self.contract_id,
                "items": [item.to_dict() for item in self.items],
                "differential": self.differential.to_dict() if self.differential else None,
            },
            sort_keys=True,
            default=str,
        )
        self.sha256_fingerprint = hashlib.sha256(raw_payload.encode()).hexdigest()
        return self.sha256_fingerprint

    def to_dict(self) -> Dict[str, Any]:
        if not self.sha256_fingerprint:
            self.compute_fingerprint()
        return {
            "finding_id": self.finding_id,
            "vulnerability_type": self.vulnerability_type,
            "target_url": self.target_url,
            "contract_id": self.contract_id,
            "items": [item.to_dict() for item in self.items],
            "differential": self.differential.to_dict() if self.differential else None,
            "reproduction_command": self.reproduction_command,
            "reproduction_steps": self.reproduction_steps,
            "confidence_score": self.confidence_score,
            "validation_status": self.validation_status,
            "sha256_fingerprint": self.sha256_fingerprint,
            "created_at": self.created_at,
        }
