"""Request Graph & Forensics Engine (§32, §34).

Constructs the central attack graph connecting:
Asset ↔ Endpoint ↔ Parameter ↔ Identity ↔ Technology ↔ Test ↔ Finding ↔ Evidence ↔ PoC.

Tracks Request mutations, differential comparisons, and provenance records.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("intelligence.request_graph")


@dataclass
class RequestNode:
    request_id: str
    target_asset: str
    endpoint: str
    method: str
    headers: Dict[str, str] = field(default_factory=dict)
    parameters: Dict[str, Any] = field(default_factory=dict)
    body: Optional[str] = None
    identity_context: str = "ANONYMOUS"
    mutation_type: str = "BASELINE"  # BASELINE, MUTATION, PROBE, CANARY
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class ResponseNode:
    request_id: str
    status_code: int
    headers: Dict[str, str] = field(default_factory=dict)
    body_snippet: str = ""
    body_hash: str = ""
    response_time_ms: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class GraphEdge:
    source_id: str
    target_id: str
    relationship: str  # DISCOVERS, MUTATES, VALIDATES, PROVES, CONNECTS_TO, OWNS
    metadata: Dict[str, Any] = field(default_factory=dict)


class RequestGraphEngine:
    """Central Intelligence Graph storing and correlating all attack-surface interactions."""

    def __init__(self) -> None:
        self._nodes: Dict[str, Dict[str, Any]] = {}
        self._edges: List[GraphEdge] = []
        self._requests: Dict[str, RequestNode] = {}
        self._responses: Dict[str, ResponseNode] = {}

    def record_interaction(
        self,
        asset: str,
        endpoint: str,
        method: str,
        req_headers: Dict[str, str],
        req_params: Dict[str, Any],
        req_body: Optional[str],
        status_code: int,
        resp_headers: Dict[str, str],
        resp_body: str,
        resp_time_ms: float,
        identity: str = "ANONYMOUS",
        mutation_type: str = "BASELINE",
        test_id: Optional[str] = None,
        finding_id: Optional[str] = None,
    ) -> str:
        """Record a full HTTP interaction, compute canonical hashes, and link to graph."""
        req_hash = hashlib.sha256(f"{method}:{endpoint}:{json_str(req_params)}:{req_body or ''}:{identity}".encode()).hexdigest()[:16]
        req_id = f"req-{req_hash}"

        body_hash = hashlib.sha256(resp_body.encode(errors="ignore")).hexdigest()
        snippet = resp_body[:500] if len(resp_body) > 500 else resp_body

        req_node = RequestNode(
            request_id=req_id,
            target_asset=asset,
            endpoint=endpoint,
            method=method.upper(),
            headers=req_headers,
            parameters=req_params,
            body=req_body,
            identity_context=identity,
            mutation_type=mutation_type,
        )
        self._requests[req_id] = req_node

        resp_node = ResponseNode(
            request_id=req_id,
            status_code=status_code,
            headers=resp_headers,
            body_snippet=snippet,
            body_hash=body_hash,
            response_time_ms=resp_time_ms,
        )
        self._responses[req_id] = resp_node

        # Add nodes to graph
        self._add_node(req_id, "HTTP_REQUEST", {
            "asset": asset,
            "endpoint": endpoint,
            "method": method,
            "status_code": status_code,
            "identity": identity,
            "mutation_type": mutation_type,
        })

        # Link to asset and endpoint
        asset_id = f"asset-{asset}"
        self._add_node(asset_id, "ASSET", {"name": asset})
        self._add_edge(req_id, asset_id, "TARGETS_ASSET")

        if test_id:
            test_node_id = f"test-{test_id}"
            self._add_node(test_node_id, "VALIDATION_TEST", {"test_id": test_id})
            self._add_edge(test_node_id, req_id, "EXECUTES_REQUEST")

        if finding_id:
            find_node_id = f"finding-{finding_id}"
            self._add_node(find_node_id, "FINDING", {"finding_id": finding_id})
            self._add_edge(req_id, find_node_id, "PROVES_FINDING")

        return req_id

    def _add_node(self, node_id: str, node_type: str, data: Dict[str, Any]) -> None:
        if node_id not in self._nodes:
            self._nodes[node_id] = {
                "id": node_id,
                "type": node_type,
                "data": data,
                "first_seen": datetime.now(timezone.utc).isoformat()
            }
        else:
            self._nodes[node_id]["data"].update(data)

    def _add_edge(self, source_id: str, target_id: str, relationship: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        self._edges.append(GraphEdge(source_id=source_id, target_id=target_id, relationship=relationship, metadata=metadata or {}))

    def get_provenance_chain(self, finding_id: str) -> Dict[str, Any]:
        """Traverse the graph and return the complete reproducible chain for a finding."""
        find_node_id = f"finding-{finding_id}"
        related_requests = [e.source_id for e in self._edges if e.target_id == find_node_id and e.relationship == "PROVES_FINDING"]
        
        chain = {
            "finding_id": finding_id,
            "evidence_requests": [],
        }

        for req_id in related_requests:
            req = self._requests.get(req_id)
            resp = self._responses.get(req_id)
            if req and resp:
                chain["evidence_requests"].append({
                    "request_id": req.request_id,
                    "method": req.method,
                    "endpoint": req.endpoint,
                    "headers": req.headers,
                    "parameters": req.parameters,
                    "body": req.body,
                    "identity": req.identity_context,
                    "response_status": resp.status_code,
                    "response_body_snippet": resp.body_snippet,
                    "response_body_hash": resp.body_hash,
                    "duration_ms": resp.response_time_ms
                })

        return chain

    def export_graph_json(self) -> Dict[str, Any]:
        """Export nodes and links for frontend visual rendering (§66)."""
        nodes_list = list(self._nodes.values())
        links_list = [
            {"source": e.source_id, "target": e.target_id, "relationship": e.relationship}
            for e in self._edges
        ]
        return {
            "nodes": nodes_list,
            "links": links_list,
            "total_nodes": len(nodes_list),
            "total_edges": len(links_list)
        }


def json_str(obj: Any) -> str:
    import json
    try:
        return json.dumps(obj, sort_keys=True)
    except Exception:
        return str(obj)


# Global Singleton Instance
request_graph = RequestGraphEngine()
