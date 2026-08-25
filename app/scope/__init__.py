"""Scope Engine & Authorization Gate (V5 §5, §102)."""
from app.scope.guard import ScopeGuard, ScopeDecision

__all__ = ["ScopeGuard", "ScopeDecision"]
