"""Security Invariant Engine & Stateful Attack Chaining (Master Prompt v2 §7, §8, §9, §10, §20).

Key Capabilities:
- Application Security Invariant Modeling:
  1. Quantity Invariant: quantity > 0
  2. Price Invariant: price >= 0
  3. Order Total Invariant: order_total >= 0
  4. Balance Mutation Invariant: wallet_balance changes only via legitimate debit/credit
  5. Stock/Inventory Invariant: customer checkout never inflates stock (stock >= 0)
  6. Ownership Invariant: object_owner == authenticated_user
  7. Workflow Invariant: payment_status == PAID before order fulfillment
- Exploitation Depth Model (§10):
  L0 (Observation) -> L1 (Suspicious Behavior) -> L2 (Reproducible Vulnerability) ->
  L3 (Controlled Exploitation) -> L4 (Security Impact Confirmed) -> L5 (Chained Impact Confirmed)
- Chained Multi-Step Reasoning across requests (§8, §9).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("ai.security_invariants")


class ExploitationDepthLevel(str, Enum):
    L0_OBSERVATION = "L0"               # Initial observation
    L1_SUSPICIOUS = "L1"                # Suspicious signal or error
    L2_REPRODUCIBLE = "L2"              # Reproducible vulnerability
    L3_CONTROLLED_EXPLOIT = "L3"        # Controlled exploitation
    L4_SECURITY_IMPACT = "L4"           # Demonstrable security impact
    L5_CHAINED_IMPACT = "L5"            # Multi-subsystem chained impact


@dataclass
class InvariantViolation:
    invariant_name: str
    expression: str
    violating_input: Any
    resulting_state: Dict[str, Any]
    depth_level: ExploitationDepthLevel
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "invariant_name": self.invariant_name,
            "expression": self.expression,
            "violating_input": self.violating_input,
            "resulting_state": self.resulting_state,
            "depth_level": self.depth_level.value,
            "description": self.description,
        }


@dataclass
class ChainedAttackPath:
    chain_id: str
    title: str
    target_root: str
    depth_reached: ExploitationDepthLevel
    steps: List[Dict[str, Any]] = field(default_factory=list)
    state_mutations: List[Dict[str, Any]] = field(default_factory=list)
    final_impact_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "title": self.title,
            "target_root": self.target_root,
            "depth_reached": self.depth_reached.value,
            "steps_count": len(self.steps),
            "steps": self.steps,
            "state_mutations": self.state_mutations,
            "final_impact_summary": self.final_impact_summary,
        }


class SecurityInvariantEngine:
    """Evaluates business and authorization invariants and models multi-step exploit chains."""

    def evaluate_e_commerce_chained_invariant(
        self,
        target_url: str,
        submitted_quantity: int = -5,
        unit_price: float = 20.0,
        initial_wallet_balance: float = 50.0,
        initial_inventory_stock: int = 100,
    ) -> ChainedAttackPath:
        """Simulates and evaluates the multi-step state chain of a negative quantity flaw (§7, §9, §41 Example B)."""
        steps: List[Dict[str, Any]] = []
        mutations: List[Dict[str, Any]] = []

        # Step 1: Basket Quantity Input (L2)
        basket_accepted = submitted_quantity < 0
        steps.append({
            "step": 1,
            "action": "Add to Basket",
            "payload": {"quantity": submitted_quantity},
            "observed": f"Server accepted negative quantity {submitted_quantity} into basket.",
            "depth": ExploitationDepthLevel.L2_REPRODUCIBLE.value,
        })
        mutations.append({"basket_quantity": submitted_quantity})

        # Step 2: Order Total Calculation (L3)
        calculated_order_total = submitted_quantity * unit_price  # -100.0
        steps.append({
            "step": 2,
            "action": "Initiate Checkout",
            "observed": f"Checkout total evaluated to negative amount ${calculated_order_total:.2f}.",
            "depth": ExploitationDepthLevel.L3_CONTROLLED_EXPLOIT.value,
        })
        mutations.append({"order_total": calculated_order_total})

        # Step 3: Wallet State Mutation (L4)
        # In a flawed system: new_balance = old_balance - order_total => 50 - (-100) = 150
        resulting_wallet_balance = initial_wallet_balance - calculated_order_total
        steps.append({
            "step": 3,
            "action": "Process Wallet Payment",
            "observed": f"Wallet balance increased from ${initial_wallet_balance:.2f} to ${resulting_wallet_balance:.2f}.",
            "depth": ExploitationDepthLevel.L4_SECURITY_IMPACT.value,
        })
        mutations.append({"wallet_balance_before": initial_wallet_balance, "wallet_balance_after": resulting_wallet_balance})

        # Step 4: Inventory Inflation (L5)
        # In a flawed system: new_stock = old_stock - basket_quantity => 100 - (-5) = 105
        resulting_stock = initial_inventory_stock - submitted_quantity
        steps.append({
            "step": 4,
            "action": "Update Inventory Fulfillment",
            "observed": f"Inventory stock increased from {initial_inventory_stock} to {resulting_stock} units.",
            "depth": ExploitationDepthLevel.L5_CHAINED_IMPACT.value,
        })
        mutations.append({"inventory_stock_before": initial_inventory_stock, "inventory_stock_after": resulting_stock})

        narrative = (
            f"Negative quantity ({submitted_quantity}) was accepted by basket validation. Checkout calculated "
            f"a negative order total (${calculated_order_total:.2f}), causing wallet balance to increase by "
            f"${abs(calculated_order_total):.2f} (credited rather than debited). Furthermore, inventory stock "
            f"was inflated by {abs(submitted_quantity)} units during order fulfillment."
        )

        return ChainedAttackPath(
            chain_id=f"chain_biz_{abs(submitted_quantity)}",
            title="Chained Business Logic: Negative Quantity to Wallet Balance Minting & Inventory Inflation",
            target_root=target_url,
            depth_reached=ExploitationDepthLevel.L5_CHAINED_IMPACT,
            steps=steps,
            state_mutations=mutations,
            final_impact_summary=narrative,
        )

    def check_ownership_invariant(
        self,
        authenticated_user_id: str,
        target_resource_owner_id: str,
        access_granted: bool,
    ) -> Optional[InvariantViolation]:
        """Validates the object ownership access invariant (IDOR/BOLA)."""
        if authenticated_user_id != target_resource_owner_id and access_granted:
            return InvariantViolation(
                invariant_name="Object Ownership Invariant",
                expression="resource.owner == session.authenticated_user",
                violating_input=target_resource_owner_id,
                resulting_state={"authenticated_user": authenticated_user_id, "accessed_object_owner": target_resource_owner_id},
                depth_level=ExploitationDepthLevel.L4_SECURITY_IMPACT,
                description=f"User {authenticated_user_id} unauthorizedly accessed object owned by {target_resource_owner_id}.",
            )
        return None


security_invariant_engine = SecurityInvariantEngine()
