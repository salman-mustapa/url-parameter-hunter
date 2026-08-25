"""Capability Registry & Gating Service (V8 §4, §5, §48).

Defines and manages all 20 security capabilities across validation levels:
L0 OBSERVE, L1 PASSIVE, L2 SAFE_ACTIVE, L3 CONTROLLED, L4 HIGH_RISK.
Enforces profile restrictions: Bug Hunt, Deep Bug Hunt, Pentest, Adversary Simulation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("services.capability_registry")


class ValidationLevel:
    L0_OBSERVE = "L0_OBSERVE"
    L1_PASSIVE = "L1_PASSIVE"
    L2_SAFE_ACTIVE = "L2_SAFE_ACTIVE"
    L3_CONTROLLED = "L3_CONTROLLED"
    L4_HIGH_RISK = "L4_HIGH_RISK"

    ALL_LEVELS = [L0_OBSERVE, L1_PASSIVE, L2_SAFE_ACTIVE, L3_CONTROLLED, L4_HIGH_RISK]


class AssessmentProfile:
    BUG_HUNT = "bug_hunt"
    DEEP_BUG_HUNT = "deep_bug_hunt"
    PENTEST = "pentest"
    ADVERSARY_SIMULATION = "adversary_simulation"

    ALL_PROFILES = [BUG_HUNT, DEEP_BUG_HUNT, PENTEST, ADVERSARY_SIMULATION]


@dataclass
class CapabilityDef:
    name: str
    category: str
    risk_level: str
    required_authorization: str
    supported_targets: List[str]
    dependencies: List[str]
    safe_mode: bool
    lab_mode: bool
    production_mode: bool
    evidence_requirements: List[str]
    cleanup_requirements: List[str]
    allowed_profiles: List[str]
    description: str


# 20 Official Capabilities defined in V8 §4
CAPABILITIES: Dict[str, CapabilityDef] = {
    "recon": CapabilityDef(
        name="recon",
        category="discovery",
        risk_level=ValidationLevel.L0_OBSERVE,
        required_authorization="STANDARD_SCOPE",
        supported_targets=["domain", "subdomain", "ip", "cidr"],
        dependencies=[],
        safe_mode=True,
        lab_mode=True,
        production_mode=True,
        evidence_requirements=["dns_records", "whois", "ct_logs"],
        cleanup_requirements=[],
        allowed_profiles=AssessmentProfile.ALL_PROFILES,
        description="Passive and active domain, DNS, and asset discovery.",
    ),
    "network": CapabilityDef(
        name="network",
        category="network",
        risk_level=ValidationLevel.L2_SAFE_ACTIVE,
        required_authorization="STANDARD_SCOPE",
        supported_targets=["ip", "domain", "port"],
        dependencies=["recon"],
        safe_mode=True,
        lab_mode=True,
        production_mode=True,
        evidence_requirements=["open_ports", "service_banners", "tls_cert"],
        cleanup_requirements=[],
        allowed_profiles=AssessmentProfile.ALL_PROFILES,
        description="Port scanning, service fingerprinting, TLS cryptography analysis.",
    ),
    "web": CapabilityDef(
        name="web",
        category="web",
        risk_level=ValidationLevel.L2_SAFE_ACTIVE,
        required_authorization="STANDARD_SCOPE",
        supported_targets=["url", "endpoint", "parameter"],
        dependencies=["network"],
        safe_mode=True,
        lab_mode=True,
        production_mode=True,
        evidence_requirements=["http_response", "headers", "parameter_list"],
        cleanup_requirements=[],
        allowed_profiles=AssessmentProfile.ALL_PROFILES,
        description="HTTP crawling, parameter mining, technology stack detection.",
    ),
    "browser": CapabilityDef(
        name="browser",
        category="browser",
        risk_level=ValidationLevel.L2_SAFE_ACTIVE,
        required_authorization="STANDARD_SCOPE",
        supported_targets=["url"],
        dependencies=["web"],
        safe_mode=True,
        lab_mode=True,
        production_mode=True,
        evidence_requirements=["screenshot", "dom_snapshot", "visual_hash"],
        cleanup_requirements=["close_browser_session"],
        allowed_profiles=[AssessmentProfile.DEEP_BUG_HUNT, AssessmentProfile.PENTEST, AssessmentProfile.ADVERSARY_SIMULATION],
        description="Headless browser inspection, DOM rendering, automated visual evidence capture.",
    ),
    "authentication": CapabilityDef(
        name="authentication",
        category="authentication",
        risk_level=ValidationLevel.L3_CONTROLLED,
        required_authorization="EXPLICIT_TEST_ACCOUNTS",
        supported_targets=["login_url", "auth_endpoint"],
        dependencies=["web"],
        safe_mode=True,
        lab_mode=True,
        production_mode=True,
        evidence_requirements=["auth_response", "session_tokens", "lockout_behavior"],
        cleanup_requirements=["revoke_test_sessions"],
        allowed_profiles=[AssessmentProfile.DEEP_BUG_HUNT, AssessmentProfile.PENTEST, AssessmentProfile.ADVERSARY_SIMULATION],
        description="Login discovery, session entropy, cookie security, bounded credential check.",
    ),
    "authorization": CapabilityDef(
        name="authorization",
        category="authorization",
        risk_level=ValidationLevel.L3_CONTROLLED,
        required_authorization="MULTI_IDENTITY_SCOPE",
        supported_targets=["api_endpoint", "object_id"],
        dependencies=["authentication"],
        safe_mode=True,
        lab_mode=True,
        production_mode=True,
        evidence_requirements=["unauthorized_response", "before_after_payloads"],
        cleanup_requirements=[],
        allowed_profiles=[AssessmentProfile.DEEP_BUG_HUNT, AssessmentProfile.PENTEST, AssessmentProfile.ADVERSARY_SIMULATION],
        description="IDOR, BOLA, privilege level crossover and role boundary verification.",
    ),
    "credential-assessment": CapabilityDef(
        name="credential-assessment",
        category="credentials",
        risk_level=ValidationLevel.L3_CONTROLLED,
        required_authorization="EXPLICIT_CREDENTIAL_TESTING",
        supported_targets=["credentials", "hashes"],
        dependencies=[],
        safe_mode=True,
        lab_mode=True,
        production_mode=True,
        evidence_requirements=["hash_classification", "entropy_measurement", "audit_record"],
        cleanup_requirements=["mask_plaintext_secrets"],
        allowed_profiles=[AssessmentProfile.PENTEST, AssessmentProfile.ADVERSARY_SIMULATION],
        description="Hash algorithm identification, work factor, password policy weakness, bounded test account validation.",
    ),
    "hash-analysis": CapabilityDef(
        name="hash-analysis",
        category="credentials",
        risk_level=ValidationLevel.L1_PASSIVE,
        required_authorization="STANDARD_SCOPE",
        supported_targets=["hash_string"],
        dependencies=[],
        safe_mode=True,
        lab_mode=True,
        production_mode=True,
        evidence_requirements=["hash_algo", "salt_detected", "entropy"],
        cleanup_requirements=[],
        allowed_profiles=AssessmentProfile.ALL_PROFILES,
        description="100% offline mathematical analysis of cryptographic hashes and strength.",
    ),
    "payload-validation": CapabilityDef(
        name="payload-validation",
        category="validation",
        risk_level=ValidationLevel.L3_CONTROLLED,
        required_authorization="EXPLICIT_VALIDATION_PERMISSION",
        supported_targets=["parameter", "input_field", "header"],
        dependencies=["web"],
        safe_mode=True,
        lab_mode=True,
        production_mode=True,
        evidence_requirements=["canary_reflection", "response_delta", "proof_of_execution"],
        cleanup_requirements=["remove_canary_artifacts"],
        allowed_profiles=AssessmentProfile.ALL_PROFILES,
        description="Harmless canary validation for SQLi, XSS, SSRF, RCE, Path Traversal.",
    ),
    "privilege-validation": CapabilityDef(
        name="privilege-validation",
        category="privilege",
        risk_level=ValidationLevel.L3_CONTROLLED,
        required_authorization="EXPLICIT_PRIVILEGE_BOUNDARY_TEST",
        supported_targets=["user_context", "role"],
        dependencies=["authorization"],
        safe_mode=True,
        lab_mode=True,
        production_mode=True,
        evidence_requirements=["before_identity", "after_authorized_state", "boundary_violation"],
        cleanup_requirements=["revert_role_changes"],
        allowed_profiles=[AssessmentProfile.PENTEST, AssessmentProfile.ADVERSARY_SIMULATION],
        description="Controlled vertical and horizontal privilege boundary assessment.",
    ),
    "lateral-movement-simulation": CapabilityDef(
        name="lateral-movement-simulation",
        category="adversary_simulation",
        risk_level=ValidationLevel.L4_HIGH_RISK,
        required_authorization="ADVERSARY_SIMULATION_EXPLICIT_APPROVAL",
        supported_targets=["internal_network", "trust_relationship"],
        dependencies=["network", "authorization"],
        safe_mode=True,  # Graph simulation by default
        lab_mode=True,
        production_mode=False,  # Mapping/Simulation only in production
        evidence_requirements=["attack_path_graph", "reachability_proof", "trust_edge"],
        cleanup_requirements=["terminate_lab_pivots"],
        allowed_profiles=[AssessmentProfile.ADVERSARY_SIMULATION],
        description="Graph-based lateral movement modeling and authorized lab reachability validation.",
    ),
    "persistence-simulation": CapabilityDef(
        name="persistence-simulation",
        category="adversary_simulation",
        risk_level=ValidationLevel.L4_HIGH_RISK,
        required_authorization="DISPOSABLE_LAB_MANDATORY_APPROVAL",
        supported_targets=["lab_environment"],
        dependencies=["lateral-movement-simulation"],
        safe_mode=False,
        lab_mode=True,
        production_mode=False,  # Strictly lab-only
        evidence_requirements=["persistence_mechanism_record", "cleanup_validation"],
        cleanup_requirements=["destroy_lab_fixture"],
        allowed_profiles=[AssessmentProfile.ADVERSARY_SIMULATION],
        description="Disposable lab-only persistence mechanism emulation with mandatory cleanup.",
    ),
    "cloud": CapabilityDef(
        name="cloud",
        category="infrastructure",
        risk_level=ValidationLevel.L2_SAFE_ACTIVE,
        required_authorization="STANDARD_SCOPE",
        supported_targets=["s3_bucket", "blob_storage", "cloud_metadata"],
        dependencies=["web"],
        safe_mode=True,
        lab_mode=True,
        production_mode=True,
        evidence_requirements=["bucket_listing", "cloud_provider_headers"],
        cleanup_requirements=[],
        allowed_profiles=AssessmentProfile.ALL_PROFILES,
        description="Public bucket exposure, cloud provider headers, SSRF cloud metadata detection.",
    ),
    "container": CapabilityDef(
        name="container",
        category="infrastructure",
        risk_level=ValidationLevel.L2_SAFE_ACTIVE,
        required_authorization="STANDARD_SCOPE",
        supported_targets=["docker_api", "kube_apiserver"],
        dependencies=["network"],
        safe_mode=True,
        lab_mode=True,
        production_mode=True,
        evidence_requirements=["daemon_version_probe", "anonymous_auth_check"],
        cleanup_requirements=[],
        allowed_profiles=[AssessmentProfile.DEEP_BUG_HUNT, AssessmentProfile.PENTEST, AssessmentProfile.ADVERSARY_SIMULATION],
        description="Docker API and Kubernetes API unauthenticated endpoint inspection.",
    ),
    "identity": CapabilityDef(
        name="identity",
        category="identity",
        risk_level=ValidationLevel.L2_SAFE_ACTIVE,
        required_authorization="STANDARD_SCOPE",
        supported_targets=["oidc_discovery", "saml_endpoint", "jwt_token"],
        dependencies=["web"],
        safe_mode=True,
        lab_mode=True,
        production_mode=True,
        evidence_requirements=["jwt_algorithm_header", "saml_metadata"],
        cleanup_requirements=[],
        allowed_profiles=AssessmentProfile.ALL_PROFILES,
        description="OIDC discovery, SAML metadata analysis, JWT signature/algorithm inspection.",
    ),
    "cve": CapabilityDef(
        name="cve",
        category="intelligence",
        risk_level=ValidationLevel.L0_OBSERVE,
        required_authorization="STANDARD_SCOPE",
        supported_targets=["cpe", "technology_version"],
        dependencies=["web", "network"],
        safe_mode=True,
        lab_mode=True,
        production_mode=True,
        evidence_requirements=["cve_catalog_match", "affected_version_matrix", "cpe_match"],
        cleanup_requirements=[],
        allowed_profiles=AssessmentProfile.ALL_PROFILES,
        description="Local offline CVE/CPE correlation and applicability reasoning.",
    ),
    "ttp": CapabilityDef(
        name="ttp",
        category="intelligence",
        risk_level=ValidationLevel.L0_OBSERVE,
        required_authorization="STANDARD_SCOPE",
        supported_targets=["finding", "observation"],
        dependencies=[],
        safe_mode=True,
        lab_mode=True,
        production_mode=True,
        evidence_requirements=["mitre_technique_id", "tactic_mapping", "evidence_link"],
        cleanup_requirements=[],
        allowed_profiles=AssessmentProfile.ALL_PROFILES,
        description="MITRE ATT&CK enterprise tactic and technique mapping with evidence binding.",
    ),
    "evidence": CapabilityDef(
        name="evidence",
        category="evidence",
        risk_level=ValidationLevel.L0_OBSERVE,
        required_authorization="STANDARD_SCOPE",
        supported_targets=["finding_data"],
        dependencies=[],
        safe_mode=True,
        lab_mode=True,
        production_mode=True,
        evidence_requirements=["sha256_hashes", "timeline_json", "reproduction_md"],
        cleanup_requirements=[],
        allowed_profiles=AssessmentProfile.ALL_PROFILES,
        description="Structured, cryptographic evidence package assembly (E0–E4).",
    ),
    "reporting": CapabilityDef(
        name="reporting",
        category="reporting",
        risk_level=ValidationLevel.L0_OBSERVE,
        required_authorization="STANDARD_SCOPE",
        supported_targets=["scan_summary"],
        dependencies=["evidence"],
        safe_mode=True,
        lab_mode=True,
        production_mode=True,
        evidence_requirements=["report_artifact", "redacted_view"],
        cleanup_requirements=[],
        allowed_profiles=AssessmentProfile.ALL_PROFILES,
        description="Executive, Technical Pentest, Bug Bounty, Retest and CVE-Ready Dossier generation.",
    ),
    "retest": CapabilityDef(
        name="retest",
        category="retest",
        risk_level=ValidationLevel.L2_SAFE_ACTIVE,
        required_authorization="STANDARD_SCOPE",
        supported_targets=["finding_id"],
        dependencies=["payload-validation"],
        safe_mode=True,
        lab_mode=True,
        production_mode=True,
        evidence_requirements=["before_evidence", "after_evidence", "diff_comparison"],
        cleanup_requirements=[],
        allowed_profiles=AssessmentProfile.ALL_PROFILES,
        description="Deterministic verification of vulnerability patches and regressions.",
    ),
    "ai-assistance": CapabilityDef(
        name="ai-assistance",
        category="ai",
        risk_level=ValidationLevel.L0_OBSERVE,
        required_authorization="STANDARD_SCOPE",
        supported_targets=["scan_context"],
        dependencies=[],
        safe_mode=True,
        lab_mode=True,
        production_mode=True,
        evidence_requirements=["ai_run_log", "ai_decision_record"],
        cleanup_requirements=[],
        allowed_profiles=AssessmentProfile.ALL_PROFILES,
        description="Local AI advisory, reasoning, test planning, evidence criticism, report drafting.",
    ),
}


class CapabilityRegistry:
    """Central registry and policy evaluator for capabilities (V8 §4)."""

    def __init__(self) -> None:
        self._capabilities: Dict[str, CapabilityDef] = CAPABILITIES

    def get_capability(self, name: str) -> Optional[CapabilityDef]:
        return self._capabilities.get(name)

    def list_capabilities(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": cap.name,
                "category": cap.category,
                "risk_level": cap.risk_level,
                "required_authorization": cap.required_authorization,
                "supported_targets": cap.supported_targets,
                "dependencies": cap.dependencies,
                "safe_mode": cap.safe_mode,
                "lab_mode": cap.lab_mode,
                "production_mode": cap.production_mode,
                "allowed_profiles": cap.allowed_profiles,
                "description": cap.description,
            }
            for cap in self._capabilities.values()
        ]

    def is_capability_allowed(
        self,
        capability_name: str,
        profile: str,
        validation_level: str = ValidationLevel.L2_SAFE_ACTIVE,
        is_lab: bool = False,
    ) -> Dict[str, Any]:
        """Evaluates whether a capability is permissible given profile and safety constraints."""
        cap = self._capabilities.get(capability_name)
        if not cap:
            return {
                "allowed": False,
                "verdict": "DENY",
                "reason": f"Unknown capability: '{capability_name}'",
            }

        # Profile normalization & alias resolution
        raw_p = profile.lower().strip()
        if raw_p in ("full", "aggressive", "adversary", "adversary_simulation", "max"):
            norm_profile = AssessmentProfile.ADVERSARY_SIMULATION
        elif raw_p in ("deep", "deep_bug_hunt", "deep_hunt"):
            norm_profile = AssessmentProfile.DEEP_BUG_HUNT
        elif raw_p in ("pentest", "pentesting"):
            norm_profile = AssessmentProfile.PENTEST
        elif raw_p in ("standard", "quick", "bug_hunt"):
            norm_profile = AssessmentProfile.BUG_HUNT
        else:
            norm_profile = raw_p

        # Elevate effective profile authorization if explicit high validation level is set
        if validation_level == ValidationLevel.L4_HIGH_RISK:
            norm_profile = AssessmentProfile.ADVERSARY_SIMULATION
        elif validation_level == ValidationLevel.L3_CONTROLLED and norm_profile == AssessmentProfile.BUG_HUNT:
            norm_profile = AssessmentProfile.DEEP_BUG_HUNT

        if norm_profile not in cap.allowed_profiles:
            return {
                "allowed": False,
                "verdict": "DENY",
                "reason": f"Capability '{capability_name}' is not permitted under '{profile}' profile.",
            }

        # High-risk L4 check
        if cap.risk_level == ValidationLevel.L4_HIGH_RISK:
            if norm_profile != AssessmentProfile.ADVERSARY_SIMULATION and validation_level != ValidationLevel.L4_HIGH_RISK:
                return {
                    "allowed": False,
                    "verdict": "DENY",
                    "reason": "L4 High-Risk capabilities are strictly disabled outside Adversary Simulation / L4 profile.",
                }
            if not is_lab and not cap.production_mode and validation_level != ValidationLevel.L4_HIGH_RISK:
                return {
                    "allowed": False,
                    "verdict": "REQUIRES_APPROVAL",
                    "reason": f"Capability '{capability_name}' requires an isolated disposable lab or explicit operator approval.",
                }

        # Validation level check
        level_hierarchy = {
            ValidationLevel.L0_OBSERVE: 0,
            ValidationLevel.L1_PASSIVE: 1,
            ValidationLevel.L2_SAFE_ACTIVE: 2,
            ValidationLevel.L3_CONTROLLED: 3,
            ValidationLevel.L4_HIGH_RISK: 4,
        }

        cap_level_val = level_hierarchy.get(cap.risk_level, 2)
        scan_level_val = level_hierarchy.get(validation_level, 2)

        if cap_level_val > scan_level_val:
            return {
                "allowed": False,
                "verdict": "REQUIRES_APPROVAL" if cap_level_val >= 3 else "DENY",
                "reason": f"Capability requires {cap.risk_level} but campaign is scoped to {validation_level}.",
            }

        return {
            "allowed": True,
            "verdict": "ALLOW",
            "reason": f"Capability '{capability_name}' is authorized under current profile and validation level.",
        }


capability_registry = CapabilityRegistry()
