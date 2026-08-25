"""Application Model — Structured Target Representation (V4 Architecture).

Extends the existing AIWorldModel with a typed, queryable application model:
- Typed entities: Asset, Endpoint, Parameter, Identity, Session, Token, Object,
  BusinessEntity, SecurityControl, TrustBoundary
- Typed relations: CONTAINS, AUTHENTICATES_AS, ACCESSES, MUTATES, TRANSITIONS_TO,
  PROTECTS, VULNERABLE_TO
- State tracking per entity (authenticated, role, permissions, balance, etc.)
- Query API for security analysis
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("models.application_model")


# ============================================================
# Entity Types
# ============================================================

class EntityType(str, Enum):
    ASSET = "Asset"
    ENDPOINT = "Endpoint"
    PARAMETER = "Parameter"
    IDENTITY = "Identity"
    SESSION = "Session"
    TOKEN = "Token"
    OBJECT = "Object"
    BUSINESS_ENTITY = "BusinessEntity"
    SECURITY_CONTROL = "SecurityControl"
    TRUST_BOUNDARY = "TrustBoundary"
    TECHNOLOGY = "Technology"
    VULNERABILITY = "Vulnerability"


class RelationType(str, Enum):
    CONTAINS = "CONTAINS"
    AUTHENTICATES_AS = "AUTHENTICATES_AS"
    ACCESSES = "ACCESSES"
    MUTATES = "MUTATES"
    TRANSITIONS_TO = "TRANSITIONS_TO"
    PROTECTS = "PROTECTS"
    VULNERABLE_TO = "VULNERABLE_TO"
    DEPENDS_ON = "DEPENDS_ON"
    EXPOSES = "EXPOSES"
    REQUIRES = "REQUIRES"


class AuthType(str, Enum):
    NONE = "none"
    SESSION_COOKIE = "session_cookie"
    JWT_BEARER = "jwt_bearer"
    API_KEY = "api_key"
    BASIC_AUTH = "basic_auth"
    OAUTH2 = "oauth2"
    CUSTOM = "custom"


# ============================================================
# Entity Dataclasses
# ============================================================

@dataclass
class ModelEntity:
    """A typed entity in the application model."""
    id: str
    entity_type: EntityType
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)
    state: Dict[str, Any] = field(default_factory=dict)
    tags: Set[str] = field(default_factory=set)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def update_state(self, **kwargs) -> None:
        self.state.update(kwargs)
        self.updated_at = time.time()

    def update_properties(self, **kwargs) -> None:
        self.properties.update(kwargs)
        self.updated_at = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "entity_type": self.entity_type.value,
            "label": self.label,
            "properties": self.properties,
            "state": self.state,
            "tags": sorted(self.tags),
        }


@dataclass
class ModelRelation:
    """A typed, directed relation between two entities."""
    id: str
    source_id: str
    target_id: str
    relation_type: RelationType
    confidence: float = 1.0
    properties: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relation_type": self.relation_type.value,
            "confidence": self.confidence,
            "properties": self.properties,
        }


# ============================================================
# Application Model
# ============================================================

class ApplicationModel:
    """Structured, queryable model of the target application.

    Represents the complete target knowledge graph including:
    - Assets, endpoints, parameters, identities, sessions, tokens
    - Objects, business entities, security controls, trust boundaries
    - Relations between all entities
    - Observable state per entity
    """

    def __init__(self, target_root: str = "global") -> None:
        self.target_root = target_root
        self._entities: Dict[str, ModelEntity] = {}
        self._relations: Dict[str, ModelRelation] = {}
        self._created_at = time.time()

        # Indexes for fast lookup
        self._by_type: Dict[EntityType, Set[str]] = {et: set() for et in EntityType}
        self._outgoing: Dict[str, List[str]] = {}  # entity_id -> [relation_ids]
        self._incoming: Dict[str, List[str]] = {}  # entity_id -> [relation_ids]

    # ---- Entity Operations ----

    def add_entity(
        self,
        entity_type: EntityType,
        label: str,
        entity_id: Optional[str] = None,
        properties: Optional[Dict[str, Any]] = None,
        state: Optional[Dict[str, Any]] = None,
        tags: Optional[Set[str]] = None,
    ) -> ModelEntity:
        """Add or update an entity."""
        eid = entity_id or f"{entity_type.value.lower()}_{uuid.uuid4().hex[:8]}"

        if eid in self._entities:
            existing = self._entities[eid]
            if properties:
                existing.update_properties(**properties)
            if state:
                existing.update_state(**state)
            if tags:
                existing.tags |= tags
            return existing

        entity = ModelEntity(
            id=eid,
            entity_type=entity_type,
            label=label,
            properties=properties or {},
            state=state or {},
            tags=tags or set(),
        )
        self._entities[eid] = entity
        self._by_type[entity_type].add(eid)
        return entity

    def get_entity(self, entity_id: str) -> Optional[ModelEntity]:
        return self._entities.get(entity_id)

    def get_entities_by_type(self, entity_type: EntityType) -> List[ModelEntity]:
        return [self._entities[eid] for eid in self._by_type.get(entity_type, set()) if eid in self._entities]

    def remove_entity(self, entity_id: str) -> bool:
        entity = self._entities.pop(entity_id, None)
        if not entity:
            return False
        self._by_type[entity.entity_type].discard(entity_id)
        # Remove associated relations
        for rid in list(self._outgoing.get(entity_id, [])):
            self._relations.pop(rid, None)
        for rid in list(self._incoming.get(entity_id, [])):
            self._relations.pop(rid, None)
        self._outgoing.pop(entity_id, None)
        self._incoming.pop(entity_id, None)
        return True

    # ---- Relation Operations ----

    def add_relation(
        self,
        source_id: str,
        target_id: str,
        relation_type: RelationType,
        confidence: float = 1.0,
        properties: Optional[Dict[str, Any]] = None,
        relation_id: Optional[str] = None,
    ) -> Optional[ModelRelation]:
        """Add a typed relation between two entities."""
        if source_id not in self._entities or target_id not in self._entities:
            logger.warning("Cannot add relation: source or target entity not found")
            return None

        rid = relation_id or f"rel_{uuid.uuid4().hex[:8]}"
        relation = ModelRelation(
            id=rid,
            source_id=source_id,
            target_id=target_id,
            relation_type=relation_type,
            confidence=confidence,
            properties=properties or {},
        )
        self._relations[rid] = relation
        self._outgoing.setdefault(source_id, []).append(rid)
        self._incoming.setdefault(target_id, []).append(rid)
        return relation

    def get_relations_from(self, entity_id: str, relation_type: Optional[RelationType] = None) -> List[ModelRelation]:
        """Get all outgoing relations from an entity."""
        rids = self._outgoing.get(entity_id, [])
        relations = [self._relations[rid] for rid in rids if rid in self._relations]
        if relation_type:
            relations = [r for r in relations if r.relation_type == relation_type]
        return relations

    def get_relations_to(self, entity_id: str, relation_type: Optional[RelationType] = None) -> List[ModelRelation]:
        """Get all incoming relations to an entity."""
        rids = self._incoming.get(entity_id, [])
        relations = [self._relations[rid] for rid in rids if rid in self._relations]
        if relation_type:
            relations = [r for r in relations if r.relation_type == relation_type]
        return relations

    # ---- Query API for Security Analysis ----

    def find_endpoints_by_auth_type(self, auth_type: AuthType) -> List[ModelEntity]:
        """Find endpoints that use a specific authentication type."""
        endpoints = self.get_entities_by_type(EntityType.ENDPOINT)
        return [e for e in endpoints if e.properties.get("auth_type") == auth_type.value]

    def find_unauthenticated_endpoints(self) -> List[ModelEntity]:
        """Find endpoints with no authentication."""
        endpoints = self.get_entities_by_type(EntityType.ENDPOINT)
        return [
            e for e in endpoints
            if e.properties.get("auth_type") in (None, "none", AuthType.NONE.value)
        ]

    def get_objects_accessible_by(self, identity_id: str) -> List[ModelEntity]:
        """Get all objects accessible by a given identity."""
        relations = self.get_relations_from(identity_id, RelationType.ACCESSES)
        return [self._entities[r.target_id] for r in relations if r.target_id in self._entities]

    def get_trust_boundaries(self) -> List[ModelEntity]:
        """Get all trust boundary entities."""
        return self.get_entities_by_type(EntityType.TRUST_BOUNDARY)

    def get_security_controls(self) -> List[ModelEntity]:
        """Get all security control entities."""
        return self.get_entities_by_type(EntityType.SECURITY_CONTROL)

    def get_state_transitions(self, entity_id: str) -> List[ModelRelation]:
        """Get all state transitions from an entity."""
        return self.get_relations_from(entity_id, RelationType.TRANSITIONS_TO)

    def find_entities_with_state(self, state_key: str, state_value: Any) -> List[ModelEntity]:
        """Find entities with a specific state value."""
        return [
            e for e in self._entities.values()
            if e.state.get(state_key) == state_value
        ]

    def get_vulnerable_entities(self) -> List[Tuple[ModelEntity, ModelRelation]]:
        """Get all entities with VULNERABLE_TO relations."""
        results = []
        for r in self._relations.values():
            if r.relation_type == RelationType.VULNERABLE_TO and r.source_id in self._entities:
                results.append((self._entities[r.source_id], r))
        return results

    def get_attack_surface_summary(self) -> Dict[str, Any]:
        """Get a structured summary of the application attack surface."""
        endpoints = self.get_entities_by_type(EntityType.ENDPOINT)
        params = self.get_entities_by_type(EntityType.PARAMETER)
        identities = self.get_entities_by_type(EntityType.IDENTITY)
        objects = self.get_entities_by_type(EntityType.OBJECT)
        controls = self.get_entities_by_type(EntityType.SECURITY_CONTROL)
        boundaries = self.get_entities_by_type(EntityType.TRUST_BOUNDARY)
        vulns = self.get_entities_by_type(EntityType.VULNERABILITY)

        # Auth breakdown
        auth_breakdown: Dict[str, int] = {}
        for ep in endpoints:
            auth = ep.properties.get("auth_type", "unknown")
            auth_breakdown[auth] = auth_breakdown.get(auth, 0) + 1

        return {
            "target_root": self.target_root,
            "total_entities": len(self._entities),
            "total_relations": len(self._relations),
            "breakdown": {
                "assets": len(self._by_type[EntityType.ASSET]),
                "endpoints": len(endpoints),
                "parameters": len(params),
                "identities": len(identities),
                "objects": len(objects),
                "security_controls": len(controls),
                "trust_boundaries": len(boundaries),
                "vulnerabilities": len(vulns),
                "technologies": len(self._by_type[EntityType.TECHNOLOGY]),
                "sessions": len(self._by_type[EntityType.SESSION]),
                "tokens": len(self._by_type[EntityType.TOKEN]),
                "business_entities": len(self._by_type[EntityType.BUSINESS_ENTITY]),
            },
            "auth_breakdown": auth_breakdown,
        }

    # ---- Graph Export ----

    def to_graph(self) -> Dict[str, Any]:
        """Export the full graph for visualization or AI reasoning."""
        return {
            "target_root": self.target_root,
            "entities": [e.to_dict() for e in self._entities.values()],
            "relations": [r.to_dict() for r in self._relations.values()],
            "summary": self.get_attack_surface_summary(),
        }

    # ---- Lifecycle ----

    def reset(self) -> None:
        self._entities.clear()
        self._relations.clear()
        self._outgoing.clear()
        self._incoming.clear()
        for s in self._by_type.values():
            s.clear()
