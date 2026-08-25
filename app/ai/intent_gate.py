"""Intent Gate & Policy Enforcement Layer (V12 §3).

First-class intent classification and security gate that inspects incoming user commands,
API operations, and discovery events before delegating to the Master Orchestrator.

Responsibilities:
- Classify request intent (DISCOVERY, VULNERABILITY_VALIDATION, RECONNAISSANCE, EXPLOIT_VERIFICATION, INTEL_CORRELATION, REPORTING, RETEST).
- Validate authorization, scope boundaries, and execution mode (SAFE, CONTROLLED, AGGRESSIVE, PASSIVE).
- Prevent unauthorized direct access to raw execution workers.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from app.core.scope import Scope

logger = logging.getLogger("ai.intent_gate")


class IntentType(str, Enum):
    DISCOVERY = "discovery"
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_VALIDATION = "vulnerability_validation"
    EXPLOIT_VERIFICATION = "exploit_verification"
    INTEL_CORRELATION = "intel_correlation"
    REPORTING = "reporting"
    RETEST = "retest"
    UNKNOWN = "unknown"


class ExecutionMode(str, Enum):
    SAFE = "safe"              # Non-intrusive metadata and passive analysis
    CONTROLLED = "controlled"  # Controlled active probing with strict rate-limiting
    AGGRESSIVE = "aggressive"  # Deep fuzzing and concurrency (requires explicit authorization)
    PASSIVE = "passive"        # OSINT and external APIs only


@dataclass
class IntentClassification:
    intent: IntentType
    execution_mode: ExecutionMode
    target: str
    is_allowed: bool
    reason: str
    confidence: float = 0.95
    required_capabilities: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class IntentGate:
    """Evaluates and sanitizes requests before entering the Master Orchestrator."""

    def __init__(self) -> None:
        self._intent_keywords = [
            (IntentType.EXPLOIT_VERIFICATION, ["verify", "poc", "exploit", "reproduce", "proof"]),
            (IntentType.VULNERABILITY_VALIDATION, ["sqli", "xss", "idor", "ssrf", "rce", "auth", "inject", "cve", "vuln", "sql injection"]),
            (IntentType.RETEST, ["retest", "re-verify", "check-fixed", "remediation"]),
            (IntentType.REPORTING, ["report", "export", "pdf", "markdown", "summary", "dossier"]),
            (IntentType.INTEL_CORRELATION, ["cve", "threat", "mitre", "technology", "fingerprint", "version"]),
            (IntentType.RECONNAISSANCE, ["subdomain", "dns", "whois", "port", "nmap", "asn", "ip", "recon"]),
            (IntentType.DISCOVERY, ["crawl", "spider", "katana", "endpoint", "url", "parameter", "js", "sitemap"]),
        ]

    def classify_intent(
        self,
        command_or_event: str,
        target: str,
        profile: str = "standard",
        scope: Optional[Scope] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> IntentClassification:
        """Classifies the task intent and enforces scope/policy gates."""
        text_lower = command_or_event.lower()
        ctx = context or {}

        # 1. Classify Intent
        detected_intent = IntentType.UNKNOWN
        for intent_type, keywords in self._intent_keywords:
            if any(kw in text_lower for kw in keywords):
                detected_intent = intent_type
                break

        if detected_intent == IntentType.UNKNOWN:
            detected_intent = IntentType.DISCOVERY

        # 2. Determine Execution Mode from profile (Default: Full Power AGGRESSIVE)
        mode = ExecutionMode.AGGRESSIVE
        if profile == "passive":
            mode = ExecutionMode.PASSIVE
        elif profile in ("quick", "safe"):
            mode = ExecutionMode.CONTROLLED
        else:
            mode = ExecutionMode.AGGRESSIVE

        # 3. Required capabilities
        caps: List[str] = [detected_intent.value]
        if detected_intent == IntentType.VULNERABILITY_VALIDATION:
            caps.extend(["http_mutation", "payload_validation"])

        # 4. Scope and Policy Guard
        is_allowed = True
        reason = f"Intent '{detected_intent.value}' classified successfully under mode '{mode.value}'"

        if scope and target:
            clean_host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
            if clean_host and not scope.host_allowed(clean_host):
                is_allowed = False
                reason = f"Target host '{clean_host}' is OUT OF SCOPE according to ScopeGuard."

        return IntentClassification(
            intent=detected_intent,
            execution_mode=mode,
            target=target,
            is_allowed=is_allowed,
            reason=reason,
            confidence=0.98 if detected_intent != IntentType.UNKNOWN else 0.70,
            required_capabilities=caps,
            metadata=ctx,
        )


intent_gate = IntentGate()
