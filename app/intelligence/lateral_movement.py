"""Lateral Movement Simulation Subsystem (V8 §18).

Models graph-based lateral movement assessment:
Asset A → Identity / Credential → Trust Relationship → Asset B → Reachability.

Production Default:
OBSERVE, MAP, SIMULATE (Zero intrusive pivoting).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.intelligence.attack_graph import AttackGraphEngine

logger = logging.getLogger("intelligence.lateral_movement")


class LateralMovementSimulator:
    """Models internal trust boundaries and potential pivot paths (V8 §18)."""

    @classmethod
    def simulate_pivots(
        cls,
        graph: AttackGraphEngine,
        compromised_node_id: str,
        is_lab: bool = False,
    ) -> Dict[str, Any]:
        """Calculates reachable trust boundaries from a simulated breach point."""
        reachable_nodes: List[Dict[str, Any]] = []

        # Find immediate edges from source node
        for edge in graph.edges:
            if edge.source_node_id == compromised_node_id:
                target_node = graph.nodes.get(edge.target_node_id)
                if target_node:
                    reachable_nodes.append({
                        "target_node": target_node.id,
                        "label": target_node.label,
                        "type": target_node.node_type,
                        "relationship": edge.edge_type,
                        "confidence": edge.confidence,
                        "simulation_mode": "LAB_DISPOSABLE" if is_lab else "GRAPH_SIMULATION_ONLY",
                    })

        logger.info("Lateral movement simulation from %s mapped %d potential pivot relationships", compromised_node_id, len(reachable_nodes))

        return {
            "origin_node": compromised_node_id,
            "mode": "LAB_ACTIVE" if is_lab else "OBSERVE_MAP_SIMULATE",
            "reachable_count": len(reachable_nodes),
            "reachable_targets": reachable_nodes,
        }


lateral_movement_simulator = LateralMovementSimulator()
