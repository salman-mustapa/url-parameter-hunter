"""Canonical assessment-profile semantics.

Scope breadth (recursive/full-domain versus one focused host) is deliberately
orthogonal to test depth.  Keeping the checks here prevents a powerful profile
from silently receiving fewer probes because a scanner only recognized the
legacy ``deep`` name.
"""

from __future__ import annotations


PASSIVE_PROFILES = frozenset({"passive", "observe"})
QUICK_PROFILES = frozenset({"quick", "safe"})
STANDARD_PROFILES = frozenset({"standard", "bug_hunt"})
DEEP_PROFILES = frozenset(
    {"deep", "full", "deep_bug_hunt", "pentest", "adversary_simulation"}
)
ACTIVE_PROFILES = STANDARD_PROFILES | DEEP_PROFILES | frozenset({"custom"})


def normalize_profile(profile: str | None) -> str:
    value = (profile or "deep_bug_hunt").strip().lower().replace("-", "_")
    aliases = {
        "focused": "deep_bug_hunt",
        "focus": "deep_bug_hunt",
        "full_scan": "deep_bug_hunt",
        "focused_scan": "deep_bug_hunt",
    }
    return aliases.get(value, value)


def is_passive_profile(profile: str | None) -> bool:
    return normalize_profile(profile) in PASSIVE_PROFILES


def is_deep_profile(profile: str | None) -> bool:
    return normalize_profile(profile) in DEEP_PROFILES


def supports_active_validation(profile: str | None) -> bool:
    return normalize_profile(profile) in ACTIVE_PROFILES
