"""Autonomous Bug Hunter Loop Orchestrator (§49, §76).

Implements the continuous autonomous security research loop:
DISCOVER → NORMALIZE → CORRELATE → PRIORITIZE → PLAN → EXECUTE → OBSERVE → COMPARE → VALIDATE → UPDATE GRAPH → SELECT NEXT ACTION

Continuously adapts next actions based on newly discovered evidence and technological signals.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set

from app.core.events import event_bus
from app.validation.precondition_engine import PreconditionStatus, precondition_engine
from app.validation.false_positive_firewall import GateDecision, false_positive_firewall
from app.intelligence.request_graph import request_graph

logger = logging.getLogger("orchestration.autonomous_loop")


@dataclass
class AutonomousAction:
    action_id: str
    action_type: str  # ENUMERATE_WORDPRESS, TEST_IDOR, TEST_SQLI, TEST_SSRF, PARSE_JS, TEST_CVE
    target: str
    priority: int  # 1 (highest) to 10
    context: Dict[str, Any] = field(default_factory=dict)
    state: str = "PENDING"  # PENDING, RUNNING, COMPLETED, SKIPPED, FAILED


class AutonomousBugHunterLoop:
    """Event-driven autonomous planner that drives the multi-stage research lifecycle."""

    def __init__(self) -> None:
        self.action_queue: List[AutonomousAction] = []
        self._processed_events: Set[str] = set()
        self._active: bool = True
        self._setup_event_listeners()

    def _setup_event_listeners(self) -> None:
        """Register autonomous triggers for real-time target discovery events."""
        event_bus.subscribe("TechnologyIdentified", self._on_technology_identified)
        event_bus.subscribe("EndpointDiscovered", self._on_endpoint_discovered)
        event_bus.subscribe("ArtifactDiscovered", self._on_artifact_discovered)
        event_bus.subscribe("PortDiscovered", self._on_port_discovered)
        event_bus.subscribe("CandidateCreated", self._on_candidate_created)

    async def _on_technology_identified(self, event_data: Dict[str, Any]) -> None:
        """Trigger: Technology identified -> Plan technology-specific enumeration & CVE checks."""
        tech_name = (event_data.get("technology") or event_data.get("name") or "").lower()
        target_url = event_data.get("url") or event_data.get("host") or ""
        scan_id = event_data.get("scan_id")

        if not target_url or not tech_name:
            return

        event_key = f"tech:{tech_name}:{target_url}"
        if event_key in self._processed_events:
            return
        self._processed_events.add(event_key)

        logger.info("AutonomousLoop: Reacting to technology '%s' on %s", tech_name, target_url)

        # Dynamic Action Selection based on technology
        if "wordpress" in tech_name:
            self._enqueue_action(
                action_type="ENUMERATE_WORDPRESS",
                target=target_url,
                priority=2,
                context={"scan_id": scan_id, "technology": "WordPress"}
            )
        elif "laravel" in tech_name:
            self._enqueue_action(
                action_type="AUDIT_FRAMEWORK_SURFACE",
                target=target_url,
                priority=3,
                context={"scan_id": scan_id, "technology": "Laravel", "check_debug": True, "check_env": True}
            )
        elif "graphql" in tech_name:
            self._enqueue_action(
                action_type="TEST_GRAPHQL_INTROSPECTION",
                target=target_url,
                priority=2,
                context={"scan_id": scan_id, "endpoint": target_url}
            )

    async def _on_endpoint_discovered(self, event_data: Dict[str, Any]) -> None:
        """Trigger: Endpoint discovered -> Evaluate preconditions & dispatch targeted tests."""
        url = event_data.get("url") or ""
        parameters = event_data.get("parameters") or []
        scan_id = event_data.get("scan_id")

        if not url:
            return

        event_key = f"endpoint:{url}"
        if event_key in self._processed_events:
            return
        self._processed_events.add(event_key)

        # Evaluate IDOR Precondition
        idor_check = precondition_engine.evaluate("IDOR", {"url": url, "parameters": parameters})
        if idor_check.status == PreconditionStatus.SATISFIED:
            self._enqueue_action(
                action_type="TEST_IDOR",
                target=url,
                priority=1,
                context={"scan_id": scan_id, "parameters": parameters, "reason": idor_check.reason}
            )

        # Evaluate SSRF Precondition
        ssrf_check = precondition_engine.evaluate("SSRF", {"url": url, "parameters": parameters})
        if ssrf_check.status == PreconditionStatus.SATISFIED:
            self._enqueue_action(
                action_type="TEST_SSRF",
                target=url,
                priority=2,
                context={"scan_id": scan_id, "parameters": parameters, "reason": ssrf_check.reason}
            )

        # If JS file -> queue JavaScript Intelligence parsing
        if url.endswith(".js") or ".js?" in url:
            self._enqueue_action(
                action_type="PARSE_JS_INTELLIGENCE",
                target=url,
                priority=3,
                context={"scan_id": scan_id, "js_url": url}
            )

    async def _on_artifact_discovered(self, event_data: Dict[str, Any]) -> None:
        """Trigger: Sensitive artifact found (.git, .env, SQL dump) -> Queue deep analysis."""
        artifact_url = event_data.get("url") or event_data.get("path") or ""
        scan_id = event_data.get("scan_id")

        if not artifact_url:
            return

        logger.info("AutonomousLoop: Artifact discovered: %s", artifact_url)
        self._enqueue_action(
            action_type="ANALYZE_DISCOVERED_ARTIFACT",
            target=artifact_url,
            priority=1,
            context={"scan_id": scan_id, "artifact_url": artifact_url}
        )

    async def _on_port_discovered(self, event_data: Dict[str, Any]) -> None:
        """Trigger: Network port open -> Plan targeted service profile probe."""
        port = int(event_data.get("port") or 0)
        host = event_data.get("host") or event_data.get("ip") or ""
        scan_id = event_data.get("scan_id")

        if port in (3306, 5432, 6379, 27017, 9200, 22, 3389):
            self._enqueue_action(
                action_type="PROBE_SERVICE_PROFILE",
                target=f"{host}:{port}",
                priority=2,
                context={"scan_id": scan_id, "host": host, "port": port}
            )

    async def _on_candidate_created(self, event_data: Dict[str, Any]) -> None:
        """Trigger: Candidate finding created -> Run False-Positive Firewall Gate."""
        if not isinstance(event_data, dict):
            return

        scan_id = event_data.get("scan_id") or (event_data.get("data", {}).get("scan_id") if isinstance(event_data.get("data"), dict) else None)
        raw_finding = event_data.get("finding") or (event_data.get("data", {}).get("finding") if isinstance(event_data.get("data"), dict) else None) or event_data
        
        finding_data = dict(raw_finding) if isinstance(raw_finding, dict) else {}
        if not scan_id:
            scan_id = finding_data.get("scan_id")

        finding_id = str(finding_data.get("id") or finding_data.get("title") or finding_data.get("vuln_type") or "candidate")
        event_key = f"candidate:{scan_id}:{finding_id}"
        if event_key in self._processed_events:
            return
        self._processed_events.add(event_key)

        evidence = finding_data.get("evidence") or event_data.get("evidence") or {}
        verdict = false_positive_firewall.evaluate_finding(finding_data, evidence)
        
        if verdict.decision == GateDecision.PASS:
            logger.info("AutonomousLoop: Candidate passed firewall -> Promoted to %s", verdict.recommended_state)
            await event_bus.publish({
                "scan_id": scan_id or "",
                "type": "FindingConfirmed",
                "event_type": "FindingConfirmed",
                "status": "CONFIRMED",
                "severity": finding_data.get("severity", "info"),
                "message": f"Finding confirmed by False-Positive Firewall ({verdict.rule_id})",
                "data": {
                    "scan_id": scan_id or "",
                    "finding": finding_data,
                    "confidence": finding_data.get("confidence", 0.95),
                    "rule_id": verdict.rule_id,
                }
            })
        else:
            logger.warning("AutonomousLoop: Candidate gated by firewall (%s): %s", verdict.rule_id, verdict.reason)

    def _enqueue_action(self, action_type: str, target: str, priority: int, context: Dict[str, Any]) -> None:
        """Add action to prioritization queue (§49, §74)."""
        action_id = f"act-{len(self.action_queue) + 1}-{action_type}"
        action = AutonomousAction(
            action_id=action_id,
            action_type=action_type,
            target=target,
            priority=priority,
            context=context,
        )
        self.action_queue.append(action)
        # Keep queue sorted by priority (lowest integer = highest priority)
        self.action_queue.sort(key=lambda a: a.priority)
        logger.info("AutonomousLoop: Enqueued action [%s] for %s (Priority: %d)", action_type, target, priority)

    def get_pending_actions(self) -> List[Dict[str, Any]]:
        """Return list of queued autonomous actions for UI telemetry stream (§67)."""
        return [
            {
                "action_id": a.action_id,
                "action_type": a.action_type,
                "target": a.target,
                "priority": a.priority,
                "state": a.state,
            }
            for a in self.action_queue if a.state == "PENDING"
        ]


# Global Singleton Instance
autonomous_loop = AutonomousBugHunterLoop()
