"""Core Security Engine — Top-Level Coordinator (V4 Architecture).

The central entry point that coordinates all subsystems:
- ApplicationModel (structured target representation)
- SecurityKnowledgeEngine (taxonomy, patterns, invariants)
- ToolRegistry (deterministic capability layer)
- StateMachineEngine (workflow tracking)
- AIReasoningLayer (intelligence layer)
- AttackPlanner (structured test orchestration)
- Existing orchestration, validation, finding, and reporting engines

Implements the master loop:
  DISCOVER → MODEL → REASON → HYPOTHESIZE → PLAN → EXECUTE → OBSERVE →
  VALIDATE → CORRELATE → PIVOT → CHAIN → MEASURE IMPACT → DEDUPLICATE →
  SCORE → REPORT

The engine is deterministic: can run the entire loop without AI (heuristic fallback mode).
Observable: emits structured events at every transition.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from app.models.application_model import ApplicationModel
from app.intelligence.knowledge_engine import SecurityKnowledgeEngine, security_knowledge_engine
from app.core.tool_registry import ToolRegistry, tool_registry
from app.core.state_machine import (
    StateMachineManager,
    create_scan_state_machine,
    create_finding_state_machine,
    create_hypothesis_state_machine,
    state_machine_manager,
)
from app.ai.reasoning_layer import AIReasoningLayer, ReasoningResult
from app.ai.attack_planner import AttackPlanner, AttackPlan, attack_planner

logger = logging.getLogger("core.security_engine")


class EnginePhase(str, Enum):
    IDLE = "IDLE"
    INITIALIZING = "INITIALIZING"
    DISCOVERING = "DISCOVERING"
    MODELING = "MODELING"
    REASONING = "REASONING"
    PLANNING = "PLANNING"
    EXECUTING = "EXECUTING"
    VALIDATING = "VALIDATING"
    REPORTING = "REPORTING"
    COMPLETED = "COMPLETED"
    ERROR = "ERROR"


@dataclass
class EngineMetrics:
    """Observable metrics for the security engine."""
    phase: EnginePhase = EnginePhase.IDLE
    scan_id: Optional[str] = None
    target: str = ""
    started_at: Optional[float] = None
    last_reasoning_at: Optional[float] = None
    reasoning_cycles: int = 0
    hypotheses_generated: int = 0
    plans_created: int = 0
    plans_completed: int = 0
    findings_suspected: int = 0
    findings_confirmed: int = 0
    findings_rejected: int = 0
    tools_invoked: int = 0
    coverage_gaps_identified: int = 0
    errors: int = 0

    def to_dict(self) -> Dict[str, Any]:
        uptime = time.time() - self.started_at if self.started_at else 0
        return {
            "phase": self.phase.value,
            "scan_id": self.scan_id,
            "target": self.target,
            "uptime_seconds": round(uptime, 1),
            "reasoning_cycles": self.reasoning_cycles,
            "hypotheses_generated": self.hypotheses_generated,
            "plans_created": self.plans_created,
            "plans_completed": self.plans_completed,
            "findings_suspected": self.findings_suspected,
            "findings_confirmed": self.findings_confirmed,
            "findings_rejected": self.findings_rejected,
            "tools_invoked": self.tools_invoked,
            "coverage_gaps_identified": self.coverage_gaps_identified,
            "errors": self.errors,
        }


class SecurityEngine:
    """Top-level coordinator for the autonomous security testing platform.

    Architecture:
    ┌─────────────────────────────────────────────────────┐
    │                 SECURITY ENGINE                      │
    │                                                      │
    │  ApplicationModel ←→ ReasoningLayer ←→ AttackPlanner │
    │         ↕                  ↕                 ↕       │
    │  KnowledgeEngine    StateMachines     ToolRegistry   │
    │                                                      │
    │  ──── Deterministic Core (runs without AI) ────      │
    │  ──── AI Layer (optional, degrades gracefully) ──    │
    └─────────────────────────────────────────────────────┘
    """

    def __init__(self) -> None:
        # Core deterministic subsystems
        self.tool_registry = tool_registry
        self.knowledge_engine = security_knowledge_engine
        self.state_machines = state_machine_manager

        # Per-scan state
        self._app_models: Dict[str, ApplicationModel] = {}
        self._reasoning_layers: Dict[str, AIReasoningLayer] = {}
        self._planners: Dict[str, AttackPlanner] = {}
        self._metrics: Dict[str, EngineMetrics] = {}

        # Global metrics
        self._global_metrics = EngineMetrics()

    # ---- Lifecycle ----

    def initialize_scan(self, scan_id: str, target: str) -> Dict[str, Any]:
        """Initialize all engine subsystems for a new scan.

        Creates:
        - ApplicationModel (per-scan target knowledge graph)
        - ScanStateMachine (lifecycle tracking)
        - AIReasoningLayer (intelligence layer)
        - AttackPlanner (test orchestration)
        - EngineMetrics (observability)
        """
        logger.info("Initializing SecurityEngine for scan %s → %s", scan_id, target)

        # Create per-scan application model
        app_model = ApplicationModel(target_root=target)
        self._app_models[scan_id] = app_model

        # Create per-scan reasoning layer
        reasoning = AIReasoningLayer(
            app_model=app_model,
            knowledge_engine=self.knowledge_engine,
            tool_registry=self.tool_registry,
        )
        self._reasoning_layers[scan_id] = reasoning

        # Create per-scan attack planner
        planner = AttackPlanner(tool_registry=self.tool_registry)
        self._planners[scan_id] = planner

        # Create scan state machine
        scan_sm = create_scan_state_machine(scan_id)
        self.state_machines.register(scan_sm)

        # Initialize metrics
        metrics = EngineMetrics(
            phase=EnginePhase.INITIALIZING,
            scan_id=scan_id,
            target=target,
            started_at=time.time(),
        )
        self._metrics[scan_id] = metrics

        return {
            "scan_id": scan_id,
            "target": target,
            "status": "initialized",
            "subsystems": {
                "application_model": "ready",
                "reasoning_layer": "ready",
                "attack_planner": "ready",
                "state_machine": scan_sm.current_state,
                "tool_registry": f"{len(self.tool_registry.list_tools())} tools",
                "knowledge_engine": self.knowledge_engine.get_summary(),
            },
        }

    def start_discovery(self, scan_id: str) -> Dict[str, Any]:
        """Transition scan to discovery phase."""
        sm = self.state_machines.get(scan_id)
        if sm:
            sm.trigger("start_discovery")
        metrics = self._metrics.get(scan_id)
        if metrics:
            metrics.phase = EnginePhase.DISCOVERING
        return {"scan_id": scan_id, "phase": "DISCOVERING"}

    def complete_discovery(self, scan_id: str) -> Dict[str, Any]:
        """Transition scan from discovery to modeling."""
        sm = self.state_machines.get(scan_id)
        if sm:
            sm.trigger("discovery_complete")
        metrics = self._metrics.get(scan_id)
        if metrics:
            metrics.phase = EnginePhase.MODELING
        return {"scan_id": scan_id, "phase": "MODELING"}

    def start_testing(self, scan_id: str) -> Dict[str, Any]:
        """Transition scan to testing phase."""
        sm = self.state_machines.get(scan_id)
        if sm:
            sm.trigger("model_ready")
        metrics = self._metrics.get(scan_id)
        if metrics:
            metrics.phase = EnginePhase.EXECUTING
        return {"scan_id": scan_id, "phase": "TESTING"}

    def start_validation(self, scan_id: str) -> Dict[str, Any]:
        """Transition scan to validation phase."""
        sm = self.state_machines.get(scan_id)
        if sm:
            sm.trigger("testing_complete")
        metrics = self._metrics.get(scan_id)
        if metrics:
            metrics.phase = EnginePhase.VALIDATING
        return {"scan_id": scan_id, "phase": "VALIDATING"}

    def start_reporting(self, scan_id: str) -> Dict[str, Any]:
        """Transition scan to reporting phase."""
        sm = self.state_machines.get(scan_id)
        if sm:
            sm.trigger("validation_complete")
        metrics = self._metrics.get(scan_id)
        if metrics:
            metrics.phase = EnginePhase.REPORTING
        return {"scan_id": scan_id, "phase": "REPORTING"}

    def complete_scan(self, scan_id: str) -> Dict[str, Any]:
        """Transition scan to completed."""
        sm = self.state_machines.get(scan_id)
        if sm:
            sm.trigger("report_generated")
        metrics = self._metrics.get(scan_id)
        if metrics:
            metrics.phase = EnginePhase.COMPLETED
        return {"scan_id": scan_id, "phase": "COMPLETED"}

    # ---- AI Reasoning ----

    def run_reasoning_cycle(self, scan_id: str) -> Optional[ReasoningResult]:
        """Execute one AI reasoning cycle for a scan."""
        reasoning = self._reasoning_layers.get(scan_id)
        metrics = self._metrics.get(scan_id)

        if not reasoning:
            logger.warning("No reasoning layer for scan %s", scan_id)
            return None

        result = reasoning.reason()

        if metrics:
            metrics.reasoning_cycles += 1
            metrics.last_reasoning_at = time.time()
            metrics.hypotheses_generated = len(reasoning.hypothesis_engine.hypotheses)
            metrics.coverage_gaps_identified = len(result.gaps_identified)

        return result

    def create_attack_plan(
        self,
        scan_id: str,
        title: str,
        target: str,
        tool_sequence: List[str],
    ) -> Optional[AttackPlan]:
        """Create an attack plan for a scan."""
        planner = self._planners.get(scan_id)
        metrics = self._metrics.get(scan_id)

        if not planner:
            return None

        plan = planner.create_plan(title=title, target=target, tool_sequence=tool_sequence)

        if metrics:
            metrics.plans_created += 1

        return plan

    def record_finding(self, scan_id: str, finding_id: str, status: str = "suspected") -> None:
        """Record a finding event in metrics."""
        metrics = self._metrics.get(scan_id)
        if not metrics:
            return

        if status == "suspected":
            metrics.findings_suspected += 1
            # Create finding state machine
            fsm = create_finding_state_machine(finding_id)
            self.state_machines.register(fsm)
        elif status == "confirmed":
            metrics.findings_confirmed += 1
        elif status == "rejected":
            metrics.findings_rejected += 1

    def record_tool_invocation(self, scan_id: str) -> None:
        """Record a tool invocation event."""
        metrics = self._metrics.get(scan_id)
        if metrics:
            metrics.tools_invoked += 1

    # ---- Query API ----

    def get_app_model(self, scan_id: str) -> Optional[ApplicationModel]:
        return self._app_models.get(scan_id)

    def get_reasoning_layer(self, scan_id: str) -> Optional[AIReasoningLayer]:
        return self._reasoning_layers.get(scan_id)

    def get_planner(self, scan_id: str) -> Optional[AttackPlanner]:
        return self._planners.get(scan_id)

    def get_metrics(self, scan_id: str) -> Optional[EngineMetrics]:
        return self._metrics.get(scan_id)

    def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get comprehensive scan status from the engine perspective."""
        sm = self.state_machines.get(scan_id)
        metrics = self._metrics.get(scan_id)
        app_model = self._app_models.get(scan_id)
        planner = self._planners.get(scan_id)

        return {
            "scan_id": scan_id,
            "state_machine": sm.to_dict() if sm else None,
            "metrics": metrics.to_dict() if metrics else None,
            "model_summary": app_model.get_attack_surface_summary() if app_model else None,
            "planner_summary": planner.get_summary() if planner else None,
            "tool_registry_summary": {
                "total_tools": len(self.tool_registry.list_tools()),
            },
            "knowledge_engine_summary": self.knowledge_engine.get_summary(),
        }

    def get_engine_status(self) -> Dict[str, Any]:
        """Get global engine status."""
        return {
            "active_scans": len(self._metrics),
            "tool_registry": {
                "total_tools": len(self.tool_registry.list_tools()),
                "categories": self.tool_registry.get_summary()["by_category"],
            },
            "knowledge_engine": self.knowledge_engine.get_summary(),
            "state_machines": self.state_machines.get_summary(),
            "scans": {
                scan_id: metrics.to_dict()
                for scan_id, metrics in self._metrics.items()
            },
        }

    # ---- Cleanup ----

    def cleanup_scan(self, scan_id: str) -> None:
        """Clean up all per-scan resources."""
        self._app_models.pop(scan_id, None)
        self._reasoning_layers.pop(scan_id, None)
        self._planners.pop(scan_id, None)
        self._metrics.pop(scan_id, None)
        self.state_machines.remove(scan_id)


# Global singleton
security_engine = SecurityEngine()
