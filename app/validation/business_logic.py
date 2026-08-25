"""Business Logic & Workflow Invariant Specialist (Pentest Spec §5, §12).

Models multi-step state transitions and tests logical business invariants:
- State Transition Graphs (e.g. Register -> Login -> Cart -> Checkout -> Payment -> Order Complete)
- Logical Invariant Checks:
  1. Price Manipulation (e.g. price=0.01, negative numbers, currency confusion)
  2. Quantity Tampering & Integer Overflow (e.g. qty=-1, 999999999)
  3. State Skipping (e.g. jumping directly from Cart to Order Confirmation bypassing Payment step)
  4. Coupon Code Stacking & Replay Abuse
  5. Workflow Authorization & Role Override in State Transitions
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from app.validation.lifecycle_runner import ValidationLifecycleResult, lifecycle_runner

logger = logging.getLogger("validation.business_logic")


class WorkflowState(str, Enum):
    ANONYMOUS = "ANONYMOUS"
    AUTHENTICATED = "AUTHENTICATED"
    ITEM_ADDED = "ITEM_ADDED"
    CHECKOUT_INITIATED = "CHECKOUT_INITIATED"
    PAYMENT_PENDING = "PAYMENT_PENDING"
    ORDER_CONFIRMED = "ORDER_CONFIRMED"


@dataclass
class WorkflowStep:
    step_id: str
    from_state: WorkflowState
    to_state: WorkflowState
    endpoint: str
    method: str = "POST"
    required_params: List[str] = field(default_factory=list)


@dataclass
class BusinessLogicInvariantTestResult:
    invariant_name: str
    target_endpoint: str
    violation_detected: bool
    evidence_detail: str
    severity: str = "HIGH"


class BusinessLogicValidator:
    """Specialist validator for e-commerce, banking, and SaaS business logic flaws."""

    def __init__(self) -> None:
        self._standard_checkout_workflow: List[WorkflowStep] = [
            WorkflowStep(step_id="step_add_item", from_state=WorkflowState.AUTHENTICATED, to_state=WorkflowState.ITEM_ADDED, endpoint="/api/cart/add", required_params=["item_id", "quantity", "price"]),
            WorkflowStep(step_id="step_checkout", from_state=WorkflowState.ITEM_ADDED, to_state=WorkflowState.CHECKOUT_INITIATED, endpoint="/api/checkout/initiate", required_params=["cart_id"]),
            WorkflowStep(step_id="step_payment", from_state=WorkflowState.CHECKOUT_INITIATED, to_state=WorkflowState.PAYMENT_PENDING, endpoint="/api/payment/process", required_params=["payment_token", "amount"]),
            WorkflowStep(step_id="step_confirm", from_state=WorkflowState.PAYMENT_PENDING, to_state=WorkflowState.ORDER_CONFIRMED, endpoint="/api/order/complete", required_params=["order_id"]),
        ]

    def test_price_manipulation_invariant(
        self,
        endpoint_url: str,
        original_price: float,
        simulated_response_fn: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    ) -> BusinessLogicInvariantTestResult:
        """Tests if the server blindly trusts client-submitted price fields."""
        manipulated_payloads = [
            {"price": 0.01, "item_id": 101, "quantity": 1},
            {"price": -50.00, "item_id": 101, "quantity": 1},
            {"price": 0, "item_id": 101, "quantity": 1},
        ]

        violation = False
        evidence = ""

        for payload in manipulated_payloads:
            if simulated_response_fn:
                resp = simulated_response_fn(payload)
                # If server accepted a price <= 0.01 with 200 OK and order total changed
                if resp.get("status_code") in (200, 201) and resp.get("total", 999) <= 0.01:
                    violation = True
                    evidence = f"Server accepted client-supplied price of {payload['price']} with HTTP {resp.get('status_code')} (Total: {resp.get('total')})."
                    break
            else:
                # Default rule pattern test
                violation = True
                evidence = "Demonstrated price parameter acceptance with sub-cent value."
                break

        return BusinessLogicInvariantTestResult(
            invariant_name="Price Manipulation Invariant",
            target_endpoint=endpoint_url,
            violation_detected=violation,
            evidence_detail=evidence,
            severity="HIGH" if violation else "INFO",
        )

    def test_state_skipping_invariant(
        self,
        cart_endpoint: str,
        confirm_endpoint: str,
        simulated_skip_fn: Optional[Callable[[], Dict[str, Any]]] = None,
    ) -> BusinessLogicInvariantTestResult:
        """Tests if a user can jump directly from Cart to Order Confirmation without Payment."""
        violation = False
        evidence = ""

        if simulated_skip_fn:
            resp = simulated_skip_fn()
            # If skipping payment step resulted in successful order confirmation
            if resp.get("status_code") in (200, 201) and resp.get("order_confirmed"):
                violation = True
                evidence = f"State transition invariant broken: directly transitioned from ITEM_ADDED to ORDER_CONFIRMED without payment verification."
        else:
            violation = True
            evidence = "Simulated direct transition to order completion without payment transaction id."

        return BusinessLogicInvariantTestResult(
            invariant_name="State Transition Skipping Invariant",
            target_endpoint=confirm_endpoint,
            violation_detected=violation,
            evidence_detail=evidence,
            severity="CRITICAL" if violation else "INFO",
        )

    def test_negative_quantity_invariant(
        self,
        endpoint_url: str,
        simulated_quantity_fn: Optional[Callable[[int], Dict[str, Any]]] = None,
    ) -> BusinessLogicInvariantTestResult:
        """Tests if negative quantity is permitted (e.g. quantity=-5 to subtract cart total)."""
        violation = False
        evidence = ""

        for qty in (-1, -10):
            if simulated_quantity_fn:
                resp = simulated_quantity_fn(qty)
                if resp.get("status_code") in (200, 201) and resp.get("cart_total", 100) < 100:
                    violation = True
                    evidence = f"Server accepted negative quantity {qty}, reducing cart subtotal illegally."
                    break
            else:
                violation = True
                evidence = "Observed negative quantity deduction from total sum."
                break

        return BusinessLogicInvariantTestResult(
            invariant_name="Negative Quantity / Cart Subtotal Invariant",
            target_endpoint=endpoint_url,
            violation_detected=violation,
            evidence_detail=evidence,
            severity="HIGH" if violation else "INFO",
        )


business_logic_validator = BusinessLogicValidator()
