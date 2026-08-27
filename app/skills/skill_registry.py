"""Cybersecurity Skill Registry, Indexer & Methodology Hub (V12 §16-§26, §49-§54).

Central hub for cybersecurity methodologies and offensive/defensive skill capabilities.
Compatible with:
- Masriyan/Claude-Code-CyberSecurity-Skill (SKILL.md format with metadata, triggers, authorization gates)
- Mukul975/Anthropic-Cybersecurity-Skills (Multi-framework mapping to ATT&CK, NIST CSF, D3FEND, etc.)

Features:
- Structured Provenance & Trust Model (UNREVIEWED, REVIEWED, APPROVED, BLOCKED, DEPRECATED)
- Progressive Disclosure for compact LLM context windows
- Skill Chaining (Recon -> Fingerprinting -> Framework -> Auth -> Vuln -> Evidence -> PoC)
- Feedback & Quality Telemetry
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("skills.registry")


class SkillStatus(str, Enum):
    UNREVIEWED = "unreviewed"
    REVIEWED = "reviewed"
    APPROVED = "approved"
    BLOCKED = "blocked"
    DEPRECATED = "deprecated"


class SkillRiskLevel(str, Enum):
    SAFE = "safe"              # Non-intrusive metadata analysis / passive checks
    CONTROLLED = "controlled"  # Single-payload injection or authenticated audit
    AGGRESSIVE = "aggressive"  # Fuzzing or high-volume active mutation


@dataclass
class SkillMetadata:
    id: str
    name: str
    version: str
    category: str
    source: str  # masriyan, anthropic, builtin, custom
    description: str
    tags: List[str] = field(default_factory=list)
    triggers: List[str] = field(default_factory=list)
    methodology: List[str] = field(default_factory=list)
    required_tools: List[str] = field(default_factory=list)
    required_capabilities: List[str] = field(default_factory=list)
    risk_level: SkillRiskLevel = SkillRiskLevel.CONTROLLED
    authorization_required: bool = True
    status: SkillStatus = SkillStatus.APPROVED
    framework_mappings: Dict[str, List[str]] = field(default_factory=dict)
    provenance: Dict[str, Any] = field(default_factory=dict)
    success_rate: float = 1.0
    execution_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "category": self.category,
            "source": self.source,
            "description": self.description,
            "tags": self.tags,
            "triggers": self.triggers,
            "methodology": self.methodology,
            "required_tools": self.required_tools,
            "required_capabilities": self.required_capabilities,
            "risk_level": self.risk_level.value,
            "authorization_required": self.authorization_required,
            "status": self.status.value,
            "framework_mappings": self.framework_mappings,
            "provenance": self.provenance,
            "success_rate": self.success_rate,
            "execution_count": self.execution_count,
        }

    def get_concise_procedure(self) -> str:
        """Returns compact methodology procedure for Progressive Disclosure in LLM prompts."""
        steps = "\n".join(f"{i+1}. {step}" for i, step in enumerate(self.methodology[:5]))
        return f"### Skill: {self.name} (v{self.version})\n{self.description}\n**Methodology:**\n{steps}"


class SkillRegistry:
    """Central registry and lifecycle manager for all cybersecurity skills."""

    def __init__(self) -> None:
        self._skills: Dict[str, SkillMetadata] = {}
        self._load_builtin_skills()

    def register_skill(self, skill: SkillMetadata) -> None:
        self._skills[skill.id] = skill
        logger.info("Registered skill '%s' [%s] status: %s", skill.name, skill.id, skill.status.value)

    def get_skill(self, skill_id: str) -> Optional[SkillMetadata]:
        return self._skills.get(skill_id)

    def list_skills(
        self,
        status: Optional[SkillStatus] = None,
        category: Optional[str] = None,
    ) -> List[SkillMetadata]:
        results = list(self._skills.values())
        if status:
            results = [s for s in results if s.status == status]
        if category:
            results = [s for s in results if s.category.lower() == category.lower()]
        return results

    def approve_skill(self, skill_id: str) -> bool:
        skill = self._skills.get(skill_id)
        if skill:
            skill.status = SkillStatus.APPROVED
            logger.info("Skill '%s' approved for autonomous execution.", skill_id)
            return True
        return False

    def block_skill(self, skill_id: str) -> bool:
        skill = self._skills.get(skill_id)
        if skill:
            skill.status = SkillStatus.BLOCKED
            logger.warning("Skill '%s' BLOCKED from execution.", skill_id)
            return True
        return False

    def record_feedback(self, skill_id: str, success: bool, duration_sec: float) -> None:
        skill = self._skills.get(skill_id)
        if skill:
            skill.execution_count += 1
            # Exponential moving average for success rate
            alpha = 0.2
            current = 1.0 if success else 0.0
            skill.success_rate = (alpha * current) + ((1 - alpha) * skill.success_rate)

    def _load_builtin_skills(self) -> None:
        """Loads core standard skills inspired by Masriyan & Anthropic skill libraries."""
        builtins = [
            SkillMetadata(
                id="skill-sqli-validation",
                name="SQL Injection Advanced Validation",
                version="3.2.0",
                category="injection",
                source="builtin/masriyan",
                description="Error-based, boolean-blind, and time-based SQL injection validation and proof extraction.",
                tags=["sqli", "injection", "database", "owasp-top-10"],
                triggers=["parameter.query", "search.endpoint", "filter.param"],
                methodology=[
                    "Analyze parameter context and DB engine signatures (MySQL, PostgreSQL, SQLite, MSSQL, Oracle).",
                    "Inject non-destructive syntactic probes (e.g. quote negation, arithmetic canaries).",
                    "Verify differential response time or DB error syntax in response body.",
                    "Extract canonical curl PoC command and verify reproduction integrity.",
                ],
                required_tools=["http-client"],
                required_capabilities=["http_mutation", "sqli_validator"],
                risk_level=SkillRiskLevel.CONTROLLED,
                framework_mappings={"mitre_attack": ["T1190"], "cwe": ["CWE-89"]},
            ),
            SkillMetadata(
                id="skill-idor-audit",
                name="IDOR & Broken Object Level Authorization",
                version="3.1.0",
                category="authorization",
                source="builtin/masriyan",
                description="Detects and validates horizontal and vertical unauthorized resource access via object identifiers.",
                tags=["idor", "bola", "authorization", "api"],
                triggers=["parameter.id", "parameter.user_id", "rest.resource"],
                methodology=[
                    "Identify numerical, UUID, or sequential identifiers in path or query parameters.",
                    "Test unauthenticated access or secondary user identity swap.",
                    "Verify if unauthorized tenant object data or sensitive PII is returned.",
                    "Construct reproducible curl PoC.",
                ],
                required_tools=["http-client"],
                required_capabilities=["http_mutation", "auth_analysis"],
                risk_level=SkillRiskLevel.CONTROLLED,
                framework_mappings={"mitre_attack": ["T1078.004"], "cwe": ["CWE-639"]},
            ),
            SkillMetadata(
                id="skill-ssrf-detection",
                name="Server-Side Request Forgery Detection",
                version="2.8.0",
                category="injection",
                source="builtin/masriyan",
                description="Evaluates user-supplied URLs for cloud metadata access and internal port interaction.",
                tags=["ssrf", "cloud", "metadata", "network"],
                triggers=["parameter.url", "parameter.dest", "parameter.redirect"],
                methodology=[
                    "Identify URL/hostname parameters in incoming HTTP request.",
                    "Probe with safe loopback or external canary DNS/HTTP collaborator token.",
                    "Inspect response headers and body for internal service banners or interaction proof.",
                ],
                required_tools=["http-client"],
                required_capabilities=["http_mutation", "ssrf_validator"],
                risk_level=SkillRiskLevel.CONTROLLED,
                framework_mappings={"mitre_attack": ["T1190", "T1090"], "cwe": ["CWE-918"]},
            ),
            SkillMetadata(
                id="skill-auth-bypass",
                name="Authentication Form & Access Control Audit",
                version="3.0.0",
                category="authentication",
                source="builtin/masriyan",
                description="Verifies login form security, default credentials, SQLi login bypass, and 403 route bypass.",
                tags=["auth", "login", "403-bypass", "credentials"],
                triggers=["auth.form_discovered", "status.403"],
                methodology=[
                    "Extract login form action, field names, and hidden CSRF tokens.",
                    "Test safe default credential pairs (admin:admin, test:test).",
                    "Test SQLi tautology authentication bypass vectors on username parameter.",
                    "Verify HTTP header bypass headers (X-Forwarded-For, X-Custom-IP-Authorization) on 403 pages.",
                ],
                required_tools=["http-client"],
                required_capabilities=["http_mutation", "auth_validator"],
                risk_level=SkillRiskLevel.CONTROLLED,
                framework_mappings={"mitre_attack": ["T1078"], "cwe": ["CWE-287"]},
            ),
            SkillMetadata(
                id="skill-xss-validation",
                name="Cross-Site Scripting Reflected & Stored Verification",
                version="3.0.0",
                category="injection",
                source="builtin/masriyan",
                description="Context-aware reflection verification and mathematical canary validation for XSS.",
                tags=["xss", "reflection", "client-side"],
                triggers=["parameter.text", "parameter.q", "parameter.msg"],
                methodology=[
                    "Send benign alphanumeric canary probe to inspect reflection context (HTML, attribute, script tag).",
                    "Verify character encoding and context escaping.",
                    "Construct context-safe proof payload without destructive alert box loops.",
                ],
                required_tools=["http-client", "browser"],
                required_capabilities=["http_mutation", "xss_validator"],
                risk_level=SkillRiskLevel.CONTROLLED,
                framework_mappings={"mitre_attack": ["T1059.007"], "cwe": ["CWE-79"]},
            ),
        ]
        for sk in builtins:
            self.register_skill(sk)


class SkillRetriever:
    """Selects and ranks relevant skills dynamically using context signals and progressive disclosure."""

    def __init__(self, registry: SkillRegistry) -> None:
        self.registry = registry

    def retrieve_skills_for_context(
        self,
        target_url: str,
        technology: Optional[str] = None,
        parameter_names: Optional[List[str]] = None,
        event_type: Optional[str] = None,
        limit: int = 3,
    ) -> List[SkillMetadata]:
        """Calculates relevance score and returns top matched APPROVED skills."""
        params = [p.lower() for p in (parameter_names or [])]
        tech = (technology or "").lower()
        ev = (event_type or "").lower()
        url_lower = target_url.lower()

        scored: List[Tuple[float, SkillMetadata]] = []
        approved_skills = self.registry.list_skills(status=SkillStatus.APPROVED)

        for skill in approved_skills:
            score = 0.0

            # Tag match
            for tag in skill.tags:
                if tag in tech or tag in ev or any(tag in p for p in params):
                    score += 0.4

            # Trigger match
            for trig in skill.triggers:
                if trig in ev or any(trig.split(".")[-1] in p for p in params):
                    score += 0.5

            # URL keyword match
            if skill.id == "skill-sqli-validation" and any(k in url_lower or k in params for k in ["search", "id", "query", "filter", "item"]):
                score += 0.6
            elif skill.id == "skill-idor-audit" and any(k in url_lower or k in params for k in ["user_id", "account", "doc", "id", "profile"]):
                score += 0.6
            elif skill.id == "skill-ssrf-detection" and any(k in url_lower or k in params for k in ["url", "dest", "redirect", "feed", "webhook"]):
                score += 0.6
            elif skill.id == "skill-auth-bypass" and any(k in url_lower for k in ["login", "admin", "auth", "signin", "portal"]):
                score += 0.7

            if score > 0.3:
                scored.append((score, skill))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [s[1] for s in scored[:limit]]

    def get_chained_next_skill(self, current_skill_id: str) -> Optional[SkillMetadata]:
        """Skill Chaining: Determines next logical methodology step."""
        chains = {
            "discovery": "skill-sqli-validation",
            "skill-auth-bypass": "skill-idor-audit",
            "skill-sqli-validation": "skill-ssrf-detection",
        }
        next_id = chains.get(current_skill_id)
        return self.registry.get_skill(next_id) if next_id else None


skill_registry = SkillRegistry()
skill_retriever = SkillRetriever(skill_registry)
