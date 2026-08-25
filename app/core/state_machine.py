"""State Machine Engine — Deterministic Workflow & Lifecycle Tracking (V4 Architecture).

Provides deterministic state machines for:
- ScanStateMachine: CREATED → DISCOVERING → MODELING → TESTING → VALIDATING → REPORTING → COMPLETED
- FindingStateMachine: SUSPECTED → TESTING → VALIDATED → CONFIRMED → REPORTED | REJECTED
- HypothesisStateMachine: FORMED → PLANNED → EXECUTING → OBSERVED → EVALUATED → CONFIRMED | REJECTED
- AttackPathStateMachine: IDENTIFIED → PRECONDITIONS_MET → STEP_EXECUTING → STEP_VALIDATED → CHAINED | BLOCKED

Each transition emits an event, requires policy approval, and supports pause/resume/checkpoint.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("core.state_machine")


# ============================================================
# State Definitions
# ============================================================

class ScanState(str, Enum):
    CREATED = "CREATED"
    DISCOVERING = "DISCOVERING"
    MODELING = "MODELING"
    TESTING = "TESTING"
    VALIDATING = "VALIDATING"
    REPORTING = "REPORTING"
    COMPLETED = "COMPLETED"
    PAUSED = "PAUSED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class FindingState(str, Enum):
    SUSPECTED = "SUSPECTED"
    TESTING = "TESTING"
    VALIDATED = "VALIDATED"
    CONFIRMED = "CONFIRMED"
    REPORTED = "REPORTED"
    REJECTED = "REJECTED"


class HypothesisState(str, Enum):
    FORMED = "FORMED"
    PLANNED = "PLANNED"
    EXECUTING = "EXECUTING"
    OBSERVED = "OBSERVED"
    EVALUATED = "EVALUATED"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"


class AttackPathState(str, Enum):
    IDENTIFIED = "IDENTIFIED"
    PRECONDITIONS_MET = "PRECONDITIONS_MET"
    STEP_EXECUTING = "STEP_EXECUTING"
    STEP_VALIDATED = "STEP_VALIDATED"
    CHAINED = "CHAINED"
    BLOCKED = "BLOCKED"


# ============================================================
# Transition Definition
# ============================================================

@dataclass
class StateTransition:
    """Defines a valid state transition."""
    from_state: str
    to_state: str
    trigger: str          # Name of the action that triggers this transition
    guard_fn: Optional[Callable[[Dict[str, Any]], bool]] = None  # Optional policy check
    description: str = ""

    def is_allowed(self, context: Optional[Dict[str, Any]] = None) -> bool:
        if self.guard_fn and context:
            try:
                return self.guard_fn(context)
            except Exception:
                return False
        return True


@dataclass
class TransitionEvent:
    """Record of a state transition that occurred."""
    machine_id: str
    machine_type: str
    from_state: str
    to_state: str
    trigger: str
    timestamp: float = field(default_factory=time.time)
    context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "machine_id": self.machine_id,
            "machine_type": self.machine_type,
            "from_state": self.from_state,
            "to_state": self.to_state,
            "trigger": self.trigger,
            "timestamp": self.timestamp,
            "context": self.context,
        }


# ============================================================
# State Machine
# ============================================================

class StateMachine:
    """A deterministic finite state machine with transition logging and policy guards."""

    def __init__(
        self,
        machine_id: str,
        machine_type: str,
        initial_state: str,
        transitions: List[StateTransition],
    ) -> None:
        self.machine_id = machine_id
        self.machine_type = machine_type
        self._current_state = initial_state
        self._transitions = transitions
        self._history: List[TransitionEvent] = []
        self._paused_state: Optional[str] = None
        self._created_at = time.time()
        self._listeners: List[Callable[[TransitionEvent], None]] = []

        # Build transition lookup
        self._transition_map: Dict[Tuple[str, str], StateTransition] = {}
        for t in transitions:
            key = (t.from_state, t.trigger)
            self._transition_map[key] = t

    @property
    def current_state(self) -> str:
        return self._current_state

    @property
    def history(self) -> List[TransitionEvent]:
        return list(self._history)

    @property
    def is_terminal(self) -> bool:
        """Check if current state has no outgoing transitions."""
        return not any(t.from_state == self._current_state for t in self._transitions)

    def can_transition(self, trigger: str, context: Optional[Dict[str, Any]] = None) -> bool:
        """Check if a transition is valid from current state with given trigger."""
        key = (self._current_state, trigger)
        transition = self._transition_map.get(key)
        if not transition:
            return False
        return transition.is_allowed(context)

    def trigger(self, trigger_name: str, context: Optional[Dict[str, Any]] = None) -> TransitionEvent:
        """Execute a state transition."""
        key = (self._current_state, trigger_name)
        transition = self._transition_map.get(key)

        if not transition:
            valid_triggers = [t.trigger for t in self._transitions if t.from_state == self._current_state]
            raise ValueError(
                f"No transition '{trigger_name}' from state '{self._current_state}'. "
                f"Valid triggers: {valid_triggers}"
            )

        if not transition.is_allowed(context):
            raise PermissionError(
                f"Transition '{trigger_name}' from '{self._current_state}' to '{transition.to_state}' "
                f"blocked by policy guard."
            )

        event = TransitionEvent(
            machine_id=self.machine_id,
            machine_type=self.machine_type,
            from_state=self._current_state,
            to_state=transition.to_state,
            trigger=trigger_name,
            context=context or {},
        )

        old_state = self._current_state
        self._current_state = transition.to_state
        self._history.append(event)

        logger.debug(
            "[%s:%s] %s → %s (trigger: %s)",
            self.machine_type, self.machine_id, old_state, transition.to_state, trigger_name
        )

        # Notify listeners
        for listener in self._listeners:
            try:
                listener(event)
            except Exception as e:
                logger.warning("Listener error: %s", e)

        return event

    def pause(self) -> Optional[str]:
        """Pause the state machine, remembering current state."""
        if self._current_state in ("PAUSED", "COMPLETED", "FAILED", "CANCELLED"):
            return None
        self._paused_state = self._current_state
        self._current_state = "PAUSED"
        return self._paused_state

    def resume(self) -> Optional[str]:
        """Resume from paused state."""
        if self._current_state != "PAUSED" or not self._paused_state:
            return None
        self._current_state = self._paused_state
        self._paused_state = None
        return self._current_state

    def checkpoint(self) -> Dict[str, Any]:
        """Create a checkpoint for persistence/recovery."""
        return {
            "machine_id": self.machine_id,
            "machine_type": self.machine_type,
            "current_state": self._current_state,
            "paused_state": self._paused_state,
            "created_at": self._created_at,
            "history": [e.to_dict() for e in self._history],
        }

    def restore(self, checkpoint: Dict[str, Any]) -> None:
        """Restore from a checkpoint."""
        self._current_state = checkpoint["current_state"]
        self._paused_state = checkpoint.get("paused_state")

    def add_listener(self, listener: Callable[[TransitionEvent], None]) -> None:
        """Register a transition event listener."""
        self._listeners.append(listener)

    def get_available_triggers(self) -> List[str]:
        """Get all valid triggers from current state."""
        return [t.trigger for t in self._transitions if t.from_state == self._current_state]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "machine_id": self.machine_id,
            "machine_type": self.machine_type,
            "current_state": self._current_state,
            "paused_state": self._paused_state,
            "available_triggers": self.get_available_triggers(),
            "is_terminal": self.is_terminal,
            "history_length": len(self._history),
        }


# ============================================================
# Factory Functions for Pre-built State Machines
# ============================================================

def create_scan_state_machine(scan_id: str) -> StateMachine:
    """Create a scan lifecycle state machine."""
    transitions = [
        StateTransition("CREATED", "DISCOVERING", "start_discovery",
                        description="Begin asset discovery phase"),
        StateTransition("DISCOVERING", "MODELING", "discovery_complete",
                        description="Discovery done, build application model"),
        StateTransition("MODELING", "TESTING", "model_ready",
                        description="Model built, begin security testing"),
        StateTransition("TESTING", "VALIDATING", "testing_complete",
                        description="All tests run, validate findings"),
        StateTransition("VALIDATING", "REPORTING", "validation_complete",
                        description="Validation done, generate report"),
        StateTransition("REPORTING", "COMPLETED", "report_generated",
                        description="Report generated, scan complete"),
        # Parallel fast-path: discovery can trigger testing immediately
        StateTransition("DISCOVERING", "TESTING", "fast_path_test",
                        description="High-priority target discovered during recon — test immediately"),
        # Error/cancel transitions
        StateTransition("DISCOVERING", "FAILED", "fatal_error"),
        StateTransition("MODELING", "FAILED", "fatal_error"),
        StateTransition("TESTING", "FAILED", "fatal_error"),
        StateTransition("VALIDATING", "FAILED", "fatal_error"),
        StateTransition("CREATED", "CANCELLED", "cancel"),
        StateTransition("DISCOVERING", "CANCELLED", "cancel"),
        StateTransition("MODELING", "CANCELLED", "cancel"),
        StateTransition("TESTING", "CANCELLED", "cancel"),
        StateTransition("VALIDATING", "CANCELLED", "cancel"),
    ]
    return StateMachine(scan_id, "ScanLifecycle", ScanState.CREATED.value, transitions)


def create_finding_state_machine(finding_id: str) -> StateMachine:
    """Create a finding lifecycle state machine."""
    transitions = [
        StateTransition("SUSPECTED", "TESTING", "begin_validation"),
        StateTransition("TESTING", "VALIDATED", "test_passed"),
        StateTransition("TESTING", "REJECTED", "test_failed"),
        StateTransition("VALIDATED", "CONFIRMED", "critic_approved"),
        StateTransition("VALIDATED", "REJECTED", "critic_rejected"),
        StateTransition("CONFIRMED", "REPORTED", "include_in_report"),
    ]
    return StateMachine(finding_id, "FindingLifecycle", FindingState.SUSPECTED.value, transitions)


def create_hypothesis_state_machine(hypothesis_id: str) -> StateMachine:
    """Create a hypothesis lifecycle state machine."""
    transitions = [
        StateTransition("FORMED", "PLANNED", "plan_created"),
        StateTransition("PLANNED", "EXECUTING", "execution_started"),
        StateTransition("EXECUTING", "OBSERVED", "result_received"),
        StateTransition("OBSERVED", "EVALUATED", "evaluation_complete"),
        StateTransition("EVALUATED", "CONFIRMED", "evidence_supports"),
        StateTransition("EVALUATED", "REJECTED", "evidence_contradicts"),
        StateTransition("EVALUATED", "FORMED", "needs_more_data",
                        description="Inconclusive, reformulate hypothesis"),
    ]
    return StateMachine(hypothesis_id, "HypothesisLifecycle", HypothesisState.FORMED.value, transitions)


def create_attack_path_state_machine(path_id: str) -> StateMachine:
    """Create an attack path lifecycle state machine."""
    transitions = [
        StateTransition("IDENTIFIED", "PRECONDITIONS_MET", "preconditions_satisfied"),
        StateTransition("IDENTIFIED", "BLOCKED", "preconditions_failed"),
        StateTransition("PRECONDITIONS_MET", "STEP_EXECUTING", "step_started"),
        StateTransition("STEP_EXECUTING", "STEP_VALIDATED", "step_succeeded"),
        StateTransition("STEP_EXECUTING", "BLOCKED", "step_failed"),
        StateTransition("STEP_VALIDATED", "STEP_EXECUTING", "next_step",
                        description="Continue to next step in chain"),
        StateTransition("STEP_VALIDATED", "CHAINED", "chain_complete"),
    ]
    return StateMachine(path_id, "AttackPathLifecycle", AttackPathState.IDENTIFIED.value, transitions)


# ============================================================
# State Machine Manager (tracks all active machines)
# ============================================================

class StateMachineManager:
    """Manages all active state machines across the platform."""

    def __init__(self) -> None:
        self._machines: Dict[str, StateMachine] = {}

    def register(self, machine: StateMachine) -> None:
        self._machines[machine.machine_id] = machine

    def get(self, machine_id: str) -> Optional[StateMachine]:
        return self._machines.get(machine_id)

    def remove(self, machine_id: str) -> bool:
        if machine_id in self._machines:
            del self._machines[machine_id]
            return True
        return False

    def list_by_type(self, machine_type: str) -> List[StateMachine]:
        return [m for m in self._machines.values() if m.machine_type == machine_type]

    def get_summary(self) -> Dict[str, Any]:
        by_type: Dict[str, List[Dict[str, Any]]] = {}
        for m in self._machines.values():
            if m.machine_type not in by_type:
                by_type[m.machine_type] = []
            by_type[m.machine_type].append(m.to_dict())
        return {
            "total_machines": len(self._machines),
            "by_type": by_type,
        }


state_machine_manager = StateMachineManager()
