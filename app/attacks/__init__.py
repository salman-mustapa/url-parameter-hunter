"""Modular Attack Techniques Registry (V15).

Exports all specialist attack modules and provides a central resolver for the engine.
"""

from __future__ import annotations

from typing import Dict, Optional

from app.attacks.artifact import ArtifactAttackModule
from app.attacks.auth import AuthAttackModule
from app.attacks.base import AttackPlan, BaseAttackModule, EvidencePackage, RiskScore, ValidationResult
from app.attacks.idor import IDORAttackModule
from app.attacks.rce import RCEAttackModule
from app.attacks.service import ServiceAttackModule
from app.attacks.sqli import SQLiAttackModule
from app.attacks.ssrf import SSRFAttackModule
from app.attacks.traversal import TraversalAttackModule
from app.attacks.upload import UploadAttackModule
from app.attacks.xss import XSSAttackModule

_REGISTRY: Dict[str, BaseAttackModule] = {
    "xss": XSSAttackModule(),
    "sqli": SQLiAttackModule(),
    "auth": AuthAttackModule(),
    "idor": IDORAttackModule(),
    "ssrf": SSRFAttackModule(),
    "traversal": TraversalAttackModule(),
    "rce": RCEAttackModule(),
    "service": ServiceAttackModule(),
    "artifact": ArtifactAttackModule(),
    "upload": UploadAttackModule(),
}


def get_attack_module(attack_type: str) -> Optional[BaseAttackModule]:
    clean = attack_type.lower().strip()
    return _REGISTRY.get(clean)


def get_all_attack_modules() -> Dict[str, BaseAttackModule]:
    return dict(_REGISTRY)


def register_attack_module(module: BaseAttackModule) -> None:
    _REGISTRY[module.attack_type.lower().strip()] = module


__all__ = [
    "AttackPlan",
    "BaseAttackModule",
    "EvidencePackage",
    "RiskScore",
    "ValidationResult",
    "XSSAttackModule",
    "SQLiAttackModule",
    "AuthAttackModule",
    "IDORAttackModule",
    "SSRFAttackModule",
    "TraversalAttackModule",
    "RCEAttackModule",
    "ServiceAttackModule",
    "ArtifactAttackModule",
    "UploadAttackModule",
    "get_attack_module",
    "get_all_attack_modules",
    "register_attack_module",
]
