"""Attack Planner — Structured Test Orchestration (V4 Architecture).

Converts hypotheses into executable, structured attack plans:
- Each AttackPlan consists of ordered AttackStep objects
- Each step specifies: tool_name, parameters, expected_outcome, abort_conditions, evidence_requirements
- Plans are validated against policy (scope, risk budget, authorization) before execution
- Plans can be multi-step chains: RECON → PROBE → VALIDATE → ESCALATE → CHAIN → VERIFY

Integrates with attack_path_engine for feasibility scoring.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from app.core.tool_registry import ToolRegistry, ToolRiskLevel
from app.ai.hypothesis_engine import HypothesisRecord

logger = logging.getLogger("ai.attack_planner")


class PlanStatus(str, Enum):
    DRAFT = "DRAFT"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    ABORTED = "ABORTED"
    FAILED = "FAILED"


class StepStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    ABORTED = "ABORTED"


@dataclass
class AbortCondition:
    """Condition that should abort the current step or plan."""
    name: str
    check_description: str
    is_plan_abort: bool = False  # If true, aborts entire plan, not just step

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "check_description": self.check_description,
            "is_plan_abort": self.is_plan_abort,
        }


@dataclass
class EvidenceRequirement:
    """Evidence that must be collected during/after a step."""
    name: str
    evidence_type: str  # "http_request", "http_response", "screenshot", "state_diff", "log"
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "evidence_type": self.evidence_type,
            "description": self.description,
        }


@dataclass
class AttackStep:
    """A single step in an attack plan."""
    step_id: str
    step_number: int
    tool_name: str
    description: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    expected_outcome: str = ""
    abort_conditions: List[AbortCondition] = field(default_factory=list)
    evidence_requirements: List[EvidenceRequirement] = field(default_factory=list)
    depends_on: List[str] = field(default_factory=list)  # step_ids
    status: StepStatus = StepStatus.PENDING
    result: Optional[Dict[str, Any]] = None
    started_at: Optional[float] = None
    completed_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "step_number": self.step_number,
            "tool_name": self.tool_name,
            "description": self.description,
            "parameters": self.parameters,
            "expected_outcome": self.expected_outcome,
            "abort_conditions": [a.to_dict() for a in self.abort_conditions],
            "evidence_requirements": [e.to_dict() for e in self.evidence_requirements],
            "depends_on": self.depends_on,
            "status": self.status.value,
            "result": self.result,
        }


@dataclass
class AttackPlan:
    """A structured, executable attack plan."""
    plan_id: str
    title: str
    hypothesis_id: Optional[str]
    target: str
    steps: List[AttackStep] = field(default_factory=list)
    status: PlanStatus = PlanStatus.DRAFT
    risk_budget: float = 10.0   # Maximum cumulative risk score allowed
    total_risk: float = 0.0
    created_at: float = field(default_factory=time.time)
    approved_at: Optional[float] = None
    completed_at: Optional[float] = None
    tags: List[str] = field(default_factory=list)

    @property
    def progress(self) -> float:
        if not self.steps:
            return 0.0
        completed = sum(1 for s in self.steps if s.status in (StepStatus.SUCCEEDED, StepStatus.SKIPPED))
        return completed / len(self.steps)

    @property
    def current_step(self) -> Optional[AttackStep]:
        for step in self.steps:
            if step.status == StepStatus.PENDING:
                return step
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "title": self.title,
            "hypothesis_id": self.hypothesis_id,
            "target": self.target,
            "status": self.status.value,
            "risk_budget": self.risk_budget,
            "total_risk": self.total_risk,
            "progress": self.progress,
            "total_steps": len(self.steps),
            "tool_sequence": [s.tool_name for s in self.steps],
            "steps": [s.to_dict() for s in self.steps],
            "tags": self.tags,
            "created_at": self.created_at,
        }


class AttackPlanner:
    """Converts hypotheses into executable, structured attack plans.

    Plans are validated against policy (scope, risk budget, authorization)
    before execution. Each step specifies tool, parameters, expected outcomes,
    abort conditions, and evidence requirements.
    """

    def __init__(self, tool_registry: Optional[ToolRegistry] = None) -> None:
        self.tool_registry = tool_registry
        self._plans: Dict[str, AttackPlan] = {}

    def set_tool_registry(self, registry: ToolRegistry) -> None:
        self.tool_registry = registry

    # ---- Plan Creation ----

    def create_plan_from_hypothesis(
        self,
        hypothesis: HypothesisRecord,
        tool_sequence: List[str],
        target: str,
    ) -> AttackPlan:
        """Create an attack plan from a hypothesis and tool sequence."""
        plan_id = f"plan_{uuid.uuid4().hex[:8]}"
        plan = AttackPlan(
            plan_id=plan_id,
            title=f"Investigate: {hypothesis.statement[:80]}",
            hypothesis_id=hypothesis.hypothesis_id,
            target=target,
            tags=["hypothesis_driven"],
        )

        for i, tool_name in enumerate(tool_sequence, start=1):
            step = self._create_step(i, tool_name, target)
            plan.steps.append(step)

        # Calculate total risk
        plan.total_risk = self._calculate_total_risk(plan)

        self._plans[plan_id] = plan
        return plan

    def create_plan(
        self,
        title: str,
        target: str,
        tool_sequence: List[str],
        hypothesis_id: Optional[str] = None,
        risk_budget: float = 10.0,
    ) -> AttackPlan:
        """Create a custom attack plan."""
        plan_id = f"plan_{uuid.uuid4().hex[:8]}"
        plan = AttackPlan(
            plan_id=plan_id,
            title=title,
            hypothesis_id=hypothesis_id,
            target=target,
            risk_budget=risk_budget,
        )

        for i, tool_name in enumerate(tool_sequence, start=1):
            step = self._create_step(i, tool_name, target)
            plan.steps.append(step)

        plan.total_risk = self._calculate_total_risk(plan)
        self._plans[plan_id] = plan
        return plan

    def _create_step(self, step_number: int, tool_name: str, target: str) -> AttackStep:
        """Create an attack step for a given tool."""
        step_id = f"step_{uuid.uuid4().hex[:8]}"
        description = f"Execute {tool_name} against {target}"
        expected_outcome = "Vulnerability indicator or clean result"

        abort_conditions = [
            AbortCondition("waf_detected", "Response contains WAF/bot-challenge signature"),
            AbortCondition("target_down", "Target returns 5xx or is unreachable", is_plan_abort=True),
        ]

        evidence_reqs = [
            EvidenceRequirement("http_exchange", "http_request", "Full HTTP request/response"),
        ]

        # Enrich from tool registry
        if self.tool_registry:
            tool = self.tool_registry.get(tool_name)
            if tool:
                description = f"{tool.description} against {target}"
                expected_outcome = f"Detection of: {', '.join(tool.capabilities[:3])}"
                if tool.risk_level in (ToolRiskLevel.HIGH, ToolRiskLevel.CRITICAL):
                    abort_conditions.append(
                        AbortCondition("high_risk_scope_check", "Verify target is in authorized scope", is_plan_abort=True)
                    )
                evidence_reqs.append(
                    EvidenceRequirement("state_diff", "state_diff", f"State before/after {tool_name} execution")
                )

        return AttackStep(
            step_id=step_id,
            step_number=step_number,
            tool_name=tool_name,
            description=description,
            parameters={"target": target},
            expected_outcome=expected_outcome,
            abort_conditions=abort_conditions,
            evidence_requirements=evidence_reqs,
        )

    # ---- Policy Validation ----

    def validate_plan(self, plan: AttackPlan) -> Dict[str, Any]:
        """Validate a plan against policy (scope, risk budget, authorization)."""
        issues: List[str] = []
        warnings: List[str] = []

        # Check risk budget
        if plan.total_risk > plan.risk_budget:
            issues.append(
                f"Plan total risk ({plan.total_risk:.1f}) exceeds budget ({plan.risk_budget:.1f})"
            )

        # Check for critical-risk tools
        if self.tool_registry:
            for step in plan.steps:
                tool = self.tool_registry.get(step.tool_name)
                if tool and tool.risk_level == ToolRiskLevel.CRITICAL:
                    warnings.append(
                        f"Step {step.step_number} uses CRITICAL-risk tool '{step.tool_name}' — requires explicit authorization"
                    )
                if not tool:
                    warnings.append(f"Step {step.step_number} references unknown tool '{step.tool_name}'")

        # Check for empty plan
        if not plan.steps:
            issues.append("Plan has no steps")

        is_valid = len(issues) == 0
        return {
            "is_valid": is_valid,
            "issues": issues,
            "warnings": warnings,
            "total_risk": plan.total_risk,
            "risk_budget": plan.risk_budget,
        }

    def approve_plan(self, plan_id: str) -> Optional[AttackPlan]:
        """Approve a plan for execution."""
        plan = self._plans.get(plan_id)
        if not plan:
            return None

        validation = self.validate_plan(plan)
        if not validation["is_valid"]:
            logger.warning("Cannot approve plan %s: %s", plan_id, validation["issues"])
            return None

        plan.status = PlanStatus.APPROVED
        plan.approved_at = time.time()
        return plan

    # ---- Plan Execution Tracking ----

    def start_plan(self, plan_id: str) -> Optional[AttackPlan]:
        """Mark a plan as executing."""
        plan = self._plans.get(plan_id)
        if plan and plan.status == PlanStatus.APPROVED:
            plan.status = PlanStatus.EXECUTING
            return plan
        return None

    def complete_step(
        self, plan_id: str, step_id: str, result: Dict[str, Any], succeeded: bool = True
    ) -> Optional[AttackStep]:
        """Record completion of a plan step."""
        plan = self._plans.get(plan_id)
        if not plan:
            return None

        for step in plan.steps:
            if step.step_id == step_id:
                step.status = StepStatus.SUCCEEDED if succeeded else StepStatus.FAILED
                step.result = result
                step.completed_at = time.time()

                # Check if plan is complete
                if all(s.status in (StepStatus.SUCCEEDED, StepStatus.SKIPPED, StepStatus.FAILED) for s in plan.steps):
                    plan.status = PlanStatus.COMPLETED
                    plan.completed_at = time.time()

                return step
        return None

    def abort_plan(self, plan_id: str, reason: str = "") -> Optional[AttackPlan]:
        """Abort a plan."""
        plan = self._plans.get(plan_id)
        if plan and plan.status in (PlanStatus.APPROVED, PlanStatus.EXECUTING):
            plan.status = PlanStatus.ABORTED
            plan.completed_at = time.time()
            for step in plan.steps:
                if step.status == StepStatus.PENDING:
                    step.status = StepStatus.ABORTED
            return plan
        return None

    # ---- Queries ----

    def get_plan(self, plan_id: str) -> Optional[AttackPlan]:
        return self._plans.get(plan_id)

    def list_plans(self, status: Optional[PlanStatus] = None) -> List[AttackPlan]:
        if status:
            return [p for p in self._plans.values() if p.status == status]
        return list(self._plans.values())

    def get_active_plans(self) -> List[AttackPlan]:
        return [p for p in self._plans.values() if p.status in (PlanStatus.APPROVED, PlanStatus.EXECUTING)]

    def get_summary(self) -> Dict[str, Any]:
        by_status: Dict[str, int] = {}
        for p in self._plans.values():
            by_status[p.status.value] = by_status.get(p.status.value, 0) + 1
        return {
            "total_plans": len(self._plans),
            "by_status": by_status,
            "active_plans": len(self.get_active_plans()),
        }

    # ---- Internal ----

    def _calculate_total_risk(self, plan: AttackPlan) -> float:
        """Calculate cumulative risk score for a plan."""
        total = 0.0
        if not self.tool_registry:
            return len(plan.steps) * 1.5  # Default estimate

        risk_scores = {
            ToolRiskLevel.SAFE: 0.5,
            ToolRiskLevel.LOW: 1.0,
            ToolRiskLevel.MEDIUM: 2.0,
            ToolRiskLevel.HIGH: 3.5,
            ToolRiskLevel.CRITICAL: 5.0,
        }

        for step in plan.steps:
            tool = self.tool_registry.get(step.tool_name)
            if tool:
                total += risk_scores.get(tool.risk_level, 1.5)
            else:
                total += 1.5  # Unknown tool default
        return round(total, 1)

    def reset(self) -> None:
        self._plans.clear()


attack_planner = AttackPlanner()
