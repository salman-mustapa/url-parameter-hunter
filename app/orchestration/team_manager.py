"""Specialist Agent Architecture V2 & Team Manager (V2 Spec §8-§27, §40).

Defines the 12 logical specialist teams and capabilities:
1. Core Orchestration (MasterOrchestrator, IntentGate, OpportunityEngine, CorrelationEngine, AttackPathEngine, ContextEngine)
2. Recon Team (ReconAgent, DNSAgent, NetworkAgent, ServiceEnumerationAgent, CloudAssetAgent)
3. Web & API Team (WebDiscoveryAgent, JavaScriptAgent, APIDiscoveryAgent, BrowserDiscoveryAgent, ArtifactExposureAgent)
4. Authorization & Identity Team (AuthenticationAgent, AuthorizationAgent, IdentityContextAgent, SessionSecurityAgent, CredentialValidationAgent)
5. Vulnerability Team (SQLiAgent, XSSAgent, IDORAgent, SSRFAgent, RCEAgent, FileSecurityAgent, WebCacheSecurityAgent, CORSAgent, CSRFAgent, JWTAgent, OAuthAgent)
6. Business Logic Team (BusinessLogicAgent, RaceConditionAgent, MassAssignmentAgent, WorkflowAuthorizationAgent, RateLimitAgent)
7. Cloud & Infrastructure Team (CloudAssetAgent, CloudStorageAgent, CloudConfigurationAgent, CloudIdentityAgent, ContainerSecurityAgent, KubernetesSecurityAgent, InfrastructureExposureAgent)
8. Artifact & Source Team (ArtifactAgent, SecretsAgent, SourceCodeAgent, DependencyAgent, SupplyChainAgent)
9. Intelligence Team (TechnologyAgent, CVEAgent, ThreatIntelAgent, FrameworkMappingAgent, RiskScoringEngine)
10. Adversary Simulation Team (AttackPathAgent, AdversarySimulationAgent, PrivilegeEscalationAgent, CredentialReuseAgent, ControlledExploitAgent, BypassAndFilterEvasionAgent)
11. Evidence Team (EvidenceAgent, EvidenceCriticAgent, VisualProofAgent, PoCAgent, EvidenceSanitizationAgent)
12. Reporting Team (ReportAgent, RetestAgent, RemediationAgent)

Decouples logical agents from permanent worker processes.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("orchestration.team_manager")


class TeamName(str, Enum):
    CORE = "Core Orchestration"
    RECON_TEAM = "Recon Team"
    WEB_TEAM = "Web & API Team"
    IDENTITY_TEAM = "Authorization & Identity Team"
    VULNERABILITY_TEAM = "Vulnerability Team"
    BUSINESS_LOGIC_TEAM = "Business Logic Team"
    CLOUD_INFRA_TEAM = "Cloud & Infrastructure Team"
    ARTIFACT_SOURCE_TEAM = "Artifact & Source Team"
    INTELLIGENCE_TEAM = "Intelligence Team"
    RED_TEAM = "Adversary Simulation Team"
    EVIDENCE_TEAM = "Evidence Team"
    REPORTING_TEAM = "Reporting Team"


class ResourceClass(str, Enum):
    DISCOVERY = "discovery"
    NETWORK = "network"
    WEB = "web"
    BROWSER = "browser"
    VALIDATION = "validation"
    INTELLIGENCE = "intelligence"
    EVIDENCE = "evidence"
    AI = "ai"
    REPORTING = "reporting"


@dataclass
class SpecialistAgent:
    id: str
    name: str
    team: TeamName
    capabilities: List[str]
    required_skills: List[str] = field(default_factory=list)
    preferred_tools: List[str] = field(default_factory=list)
    allowed_modes: List[str] = field(default_factory=lambda: ["SAFE", "CONTROLLED", "LAB"])
    risk_profile: str = "controlled"  # safe, controlled, aggressive
    resource_class: str = ResourceClass.VALIDATION.value
    concurrency_weight: int = 1
    active_tasks: List[str] = field(default_factory=list)
    max_concurrency: int = 5

    # Backward compatibility properties
    @property
    def allowed_tools(self) -> List[str]:
        return self.preferred_tools

    @property
    def worker_class(self) -> str:
        return f"worker-{self.resource_class}"

    @property
    def risk_level(self) -> str:
        return self.risk_profile

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "team": self.team.value,
            "capabilities": self.capabilities,
            "required_skills": self.required_skills,
            "preferred_tools": self.preferred_tools,
            "allowed_tools": self.preferred_tools,
            "allowed_modes": self.allowed_modes,
            "risk_profile": self.risk_profile,
            "risk_level": self.risk_profile,
            "resource_class": self.resource_class,
            "worker_class": self.worker_class,
            "concurrency_weight": self.concurrency_weight,
            "active_tasks_count": len(self.active_tasks),
            "max_concurrency": self.max_concurrency,
        }


@dataclass
class AgentResult:
    agent_id: str
    status: str  # success, partial, failure, blocked
    observation: str
    confidence: float = 0.9
    evidence_ids: List[str] = field(default_factory=list)
    created_tasks: List[Dict[str, Any]] = field(default_factory=list)
    recommended_next_actions: List[str] = field(default_factory=list)
    emitted_events: List[Dict[str, Any]] = field(default_factory=list)
    execution_time_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "status": self.status,
            "observation": self.observation,
            "confidence": self.confidence,
            "evidence_ids": self.evidence_ids,
            "created_tasks": self.created_tasks,
            "recommended_next_actions": self.recommended_next_actions,
            "emitted_events": self.emitted_events,
            "execution_time_seconds": self.execution_time_seconds,
        }


class TeamManager:
    """Coordinates specialist teams and manages parallel capability routing."""

    def __init__(self) -> None:
        self.agents: Dict[str, SpecialistAgent] = {}
        self._initialize_specialists()

    def _initialize_specialists(self) -> None:
        """Initializes standard specialist agents across all 12 teams."""
        specialists: List[SpecialistAgent] = [
            # -------------------------------------------------------------
            # 1. RECON TEAM
            # -------------------------------------------------------------
            SpecialistAgent(
                id="recon",
                name="ReconAgent",
                team=TeamName.RECON_TEAM,
                capabilities=["subdomain_enum", "root_discovery", "cname_permutation", "wildcard_detection", "passive_intel"],
                required_skills=["subdomain-enumeration", "reconnaissance"],
                preferred_tools=["subfinder", "amass", "crtsh"],
                resource_class=ResourceClass.DISCOVERY.value,
                risk_profile="safe",
            ),
            SpecialistAgent(
                id="dns",
                name="DNSAgent",
                team=TeamName.RECON_TEAM,
                capabilities=["dns_resolution", "dns_record_analysis", "cname_relationship", "dns_anomalies", "zone_transfer"],
                required_skills=["dns-analysis"],
                preferred_tools=["dnsx", "dig"],
                resource_class=ResourceClass.DISCOVERY.value,
                risk_profile="safe",
            ),
            SpecialistAgent(
                id="network",
                name="NetworkAgent",
                team=TeamName.RECON_TEAM,
                capabilities=["port_scan", "service_detection", "tls_probe", "banner_grabbing", "os_fingerprinting"],
                required_skills=["network-scanning", "service-identification"],
                preferred_tools=["nmap", "naabu", "httpx"],
                resource_class=ResourceClass.NETWORK.value,
                risk_profile="controlled",
            ),
            SpecialistAgent(
                id="service_enum",
                name="ServiceEnumerationAgent",
                team=TeamName.RECON_TEAM,
                capabilities=["ssh_audit", "smtp_enum", "snmp_probe", "rdp_check", "smb_enum"],
                required_skills=["service-enumeration"],
                preferred_tools=["nmap", "hydra"],
                resource_class=ResourceClass.NETWORK.value,
                risk_profile="controlled",
            ),
            SpecialistAgent(
                id="cloud_asset",
                name="CloudAssetAgent",
                team=TeamName.RECON_TEAM,
                capabilities=["cloud_asset_discovery", "storage_exposure_check", "cloud_hostname_correlation", "cloud_service_id"],
                required_skills=["cloud-reconnaissance"],
                preferred_tools=["httpx", "http-client"],
                resource_class=ResourceClass.DISCOVERY.value,
                risk_profile="safe",
            ),

            # -------------------------------------------------------------
            # 2. WEB & API TEAM
            # -------------------------------------------------------------
            SpecialistAgent(
                id="web_discovery",
                name="WebDiscoveryAgent",
                team=TeamName.WEB_TEAM,
                capabilities=["web_crawler", "path_discovery", "form_discovery", "param_miner", "spa_detection", "soft_404_intel"],
                required_skills=["web-crawling", "parameter-discovery"],
                preferred_tools=["katana", "gau", "paramspider"],
                resource_class=ResourceClass.WEB.value,
                risk_profile="safe",
            ),
            SpecialistAgent(
                id="javascript",
                name="JavaScriptAgent",
                team=TeamName.WEB_TEAM,
                capabilities=["js_endpoint_extraction", "route_extraction", "api_extraction", "source_map_analysis", "config_extraction"],
                required_skills=["javascript-analysis", "source-map-unpacking"],
                preferred_tools=["jsluice", "unmap", "http-client"],
                resource_class=ResourceClass.WEB.value,
                risk_profile="safe",
            ),
            SpecialistAgent(
                id="api_discovery",
                name="APIDiscoveryAgent",
                team=TeamName.WEB_TEAM,
                capabilities=["rest_discovery", "graphql_discovery", "openapi_discovery", "swagger_enum", "websocket_probe", "soap_wsdl_audit"],
                required_skills=["api-discovery", "graphql-introspection"],
                preferred_tools=["httpx", "graphql-cli"],
                resource_class=ResourceClass.WEB.value,
                risk_profile="safe",
            ),
            SpecialistAgent(
                id="browser_discovery",
                name="BrowserDiscoveryAgent",
                team=TeamName.WEB_TEAM,
                capabilities=["spa_route_discovery", "client_api_discovery", "dynamic_dom_behavior", "auth_flow_navigation"],
                required_skills=["browser-automation"],
                preferred_tools=["playwright", "puppeteer"],
                resource_class=ResourceClass.BROWSER.value,
                risk_profile="controlled",
            ),
            SpecialistAgent(
                id="artifact_exposure",
                name="ArtifactExposureAgent",
                team=TeamName.WEB_TEAM,
                capabilities=["backup_file_discovery", "directory_listing_check", "hidden_admin_portal_exposure"],
                required_skills=["content-discovery"],
                preferred_tools=["ffuf", "dirsearch"],
                resource_class=ResourceClass.WEB.value,
                risk_profile="safe",
            ),

            # -------------------------------------------------------------
            # 3. AUTHORIZATION & IDENTITY TEAM
            # -------------------------------------------------------------
            SpecialistAgent(
                id="authentication",
                name="AuthenticationAgent",
                team=TeamName.IDENTITY_TEAM,
                capabilities=["auth_bypass_validation", "credential_stuffing_detection", "mfa_bypass_analysis", "password_reset_audit"],
                required_skills=["authentication-testing"],
                preferred_tools=["http-client"],
                resource_class=ResourceClass.VALIDATION.value,
                risk_profile="controlled",
            ),
            SpecialistAgent(
                id="authorization",
                name="AuthorizationAgent",
                team=TeamName.IDENTITY_TEAM,
                capabilities=["broken_object_level_auth", "function_level_auth_bypass", "privilege_matrix_audit", "tenant_isolation_check"],
                required_skills=["authorization-testing", "bfla"],
                preferred_tools=["http-client"],
                resource_class=ResourceClass.VALIDATION.value,
                risk_profile="controlled",
            ),
            SpecialistAgent(
                id="identity_context",
                name="IdentityContextAgent",
                team=TeamName.IDENTITY_TEAM,
                capabilities=["multi_role_differential_test", "role_elevation_mapping", "token_switching"],
                required_skills=["identity-correlation"],
                preferred_tools=["http-client"],
                resource_class=ResourceClass.VALIDATION.value,
                risk_profile="controlled",
            ),
            SpecialistAgent(
                id="session_security",
                name="SessionSecurityAgent",
                team=TeamName.IDENTITY_TEAM,
                capabilities=["session_fixation", "session_hijacking_indicator", "cookie_attribute_audit", "token_entropy_check"],
                required_skills=["session-management"],
                preferred_tools=["http-client"],
                resource_class=ResourceClass.VALIDATION.value,
                risk_profile="safe",
            ),
            SpecialistAgent(
                id="credential_validation",
                name="CredentialValidationAgent",
                team=TeamName.IDENTITY_TEAM,
                capabilities=["credential_spray_validation", "hash_cracking_check", "default_credential_probe"],
                required_skills=["credential-auditing"],
                preferred_tools=["hydra", "http-client"],
                resource_class=ResourceClass.VALIDATION.value,
                risk_profile="controlled",
            ),

            # -------------------------------------------------------------
            # 4. VULNERABILITY TEAM
            # -------------------------------------------------------------
            SpecialistAgent(
                id="sqli",
                name="SQLiAgent",
                team=TeamName.VULNERABILITY_TEAM,
                capabilities=["sqli_validation", "boolean_sqli", "time_based_sqli", "error_based_sqli", "stacked_queries"],
                required_skills=["sqli-validation", "sql-injection"],
                preferred_tools=["ghauri", "sqlmap", "http-client"],
                resource_class=ResourceClass.VALIDATION.value,
                risk_profile="controlled",
            ),
            SpecialistAgent(
                id="xss",
                name="XSSAgent",
                team=TeamName.VULNERABILITY_TEAM,
                capabilities=["xss_validation", "reflected_xss", "stored_xss", "dom_xss", "csp_bypass_analysis"],
                required_skills=["xss-validation"],
                preferred_tools=["dalfox", "playwright", "http-client"],
                resource_class=ResourceClass.VALIDATION.value,
                risk_profile="controlled",
            ),
            SpecialistAgent(
                id="idor",
                name="IDORAgent",
                team=TeamName.VULNERABILITY_TEAM,
                capabilities=["idor_validation", "horizontal_idor", "vertical_idor", "uuid_predictable_probe"],
                required_skills=["idor-validation"],
                preferred_tools=["http-client"],
                resource_class=ResourceClass.VALIDATION.value,
                risk_profile="controlled",
            ),
            SpecialistAgent(
                id="ssrf",
                name="SSRFAgent",
                team=TeamName.VULNERABILITY_TEAM,
                capabilities=["ssrf_validation", "blind_ssrf", "cloud_metadata_ssrf", "interactsh_oob_verify"],
                required_skills=["ssrf-validation"],
                preferred_tools=["interactsh", "http-client"],
                resource_class=ResourceClass.VALIDATION.value,
                risk_profile="controlled",
            ),
            SpecialistAgent(
                id="rce",
                name="RCEAgent",
                team=TeamName.VULNERABILITY_TEAM,
                capabilities=["rce_validation", "command_injection", "ssti_validation", "deserialization_probe", "oob_rce"],
                required_skills=["rce-validation", "command-injection"],
                preferred_tools=["interactsh", "http-client"],
                resource_class=ResourceClass.VALIDATION.value,
                risk_profile="aggressive",
            ),
            SpecialistAgent(
                id="file_security",
                name="FileSecurityAgent",
                team=TeamName.VULNERABILITY_TEAM,
                capabilities=["lfi_validation", "rfi_validation", "path_traversal", "unrestricted_file_upload"],
                required_skills=["lfi-validation", "file-upload-bypass"],
                preferred_tools=["http-client"],
                resource_class=ResourceClass.VALIDATION.value,
                risk_profile="controlled",
            ),
            SpecialistAgent(
                id="web_cache",
                name="WebCacheSecurityAgent",
                team=TeamName.VULNERABILITY_TEAM,
                capabilities=["web_cache_poisoning", "cache_deception", "keyed_unkeyed_param_check"],
                required_skills=["cache-poisoning"],
                preferred_tools=["http-client"],
                resource_class=ResourceClass.VALIDATION.value,
                risk_profile="controlled",
            ),
            SpecialistAgent(
                id="cors",
                name="CORSAgent",
                team=TeamName.VULNERABILITY_TEAM,
                capabilities=["cors_misconfig_validation", "origin_reflection_check", "null_origin_bypass", "credentials_leak"],
                required_skills=["cors-misconfiguration"],
                preferred_tools=["http-client"],
                resource_class=ResourceClass.VALIDATION.value,
                risk_profile="safe",
            ),
            SpecialistAgent(
                id="csrf",
                name="CSRFAgent",
                team=TeamName.VULNERABILITY_TEAM,
                capabilities=["csrf_validation", "samesite_cookie_audit", "state_change_precondition"],
                required_skills=["csrf-validation"],
                preferred_tools=["http-client"],
                resource_class=ResourceClass.VALIDATION.value,
                risk_profile="safe",
            ),
            SpecialistAgent(
                id="jwt",
                name="JWTAgent",
                team=TeamName.VULNERABILITY_TEAM,
                capabilities=["jwt_none_alg_bypass", "jwt_weak_hmac_secret", "jwt_header_injection", "jwt_kid_injection"],
                required_skills=["jwt-security"],
                preferred_tools=["jwt-tool", "http-client"],
                resource_class=ResourceClass.VALIDATION.value,
                risk_profile="controlled",
            ),
            SpecialistAgent(
                id="oauth",
                name="OAuthAgent",
                team=TeamName.VULNERABILITY_TEAM,
                capabilities=["oauth_redirect_uri_hijack", "oauth_state_omission", "pkce_downgrade", "token_leakage"],
                required_skills=["oauth-security"],
                preferred_tools=["http-client"],
                resource_class=ResourceClass.VALIDATION.value,
                risk_profile="controlled",
            ),

            # -------------------------------------------------------------
            # 5. BUSINESS LOGIC TEAM
            # -------------------------------------------------------------
            SpecialistAgent(
                id="biz_logic",
                name="BusinessLogicAgent",
                team=TeamName.BUSINESS_LOGIC_TEAM,
                capabilities=["price_manipulation_check", "step_skipping_audit", "quantity_overflow_probe"],
                required_skills=["business-logic-flaws"],
                preferred_tools=["http-client"],
                resource_class=ResourceClass.VALIDATION.value,
                risk_profile="controlled",
            ),
            SpecialistAgent(
                id="race_condition",
                name="RaceConditionAgent",
                team=TeamName.BUSINESS_LOGIC_TEAM,
                capabilities=["race_condition_validation", "single_packet_attack", "limit_overrun"],
                required_skills=["race-conditions"],
                preferred_tools=["http-client"],
                resource_class=ResourceClass.VALIDATION.value,
                risk_profile="controlled",
            ),
            SpecialistAgent(
                id="mass_assignment",
                name="MassAssignmentAgent",
                team=TeamName.BUSINESS_LOGIC_TEAM,
                capabilities=["mass_assignment_probe", "admin_param_injection", "role_override_check"],
                required_skills=["mass-assignment"],
                preferred_tools=["http-client"],
                resource_class=ResourceClass.VALIDATION.value,
                risk_profile="controlled",
            ),
            SpecialistAgent(
                id="workflow_auth",
                name="WorkflowAuthorizationAgent",
                team=TeamName.BUSINESS_LOGIC_TEAM,
                capabilities=["workflow_bypass", "state_transition_violation"],
                required_skills=["workflow-security"],
                preferred_tools=["http-client"],
                resource_class=ResourceClass.VALIDATION.value,
                risk_profile="controlled",
            ),
            SpecialistAgent(
                id="rate_limit",
                name="RateLimitAgent",
                team=TeamName.BUSINESS_LOGIC_TEAM,
                capabilities=["rate_limit_bypass", "ip_header_spoofing", "captcha_bypass_analysis"],
                required_skills=["rate-limiting"],
                preferred_tools=["http-client"],
                resource_class=ResourceClass.VALIDATION.value,
                risk_profile="safe",
            ),

            # -------------------------------------------------------------
            # 6. CLOUD & INFRASTRUCTURE TEAM
            # -------------------------------------------------------------
            SpecialistAgent(
                id="cloud_storage",
                name="CloudStorageAgent",
                team=TeamName.CLOUD_INFRA_TEAM,
                capabilities=["s3_public_read_write", "blob_anonymous_access", "gcs_bucket_exposure"],
                required_skills=["cloud-storage-security"],
                preferred_tools=["http-client", "aws-cli"],
                resource_class=ResourceClass.DISCOVERY.value,
                risk_profile="controlled",
            ),
            SpecialistAgent(
                id="cloud_config",
                name="CloudConfigurationAgent",
                team=TeamName.CLOUD_INFRA_TEAM,
                capabilities=["iam_policy_misconfig", "metadata_service_leak", "exposed_management_console"],
                required_skills=["cloud-configuration"],
                preferred_tools=["http-client"],
                resource_class=ResourceClass.INTELLIGENCE.value,
                risk_profile="safe",
            ),
            SpecialistAgent(
                id="container_security",
                name="ContainerSecurityAgent",
                team=TeamName.CLOUD_INFRA_TEAM,
                capabilities=["docker_socket_exposure", "container_escape_indicators", "unauthenticated_registry_check"],
                required_skills=["container-security"],
                preferred_tools=["http-client"],
                resource_class=ResourceClass.NETWORK.value,
                risk_profile="controlled",
            ),
            SpecialistAgent(
                id="k8s_security",
                name="KubernetesSecurityAgent",
                team=TeamName.CLOUD_INFRA_TEAM,
                capabilities=["k8s_api_server_unauth", "kubelet_readonly_exposure", "etcd_unauthenticated_check"],
                required_skills=["kubernetes-security"],
                preferred_tools=["http-client"],
                resource_class=ResourceClass.NETWORK.value,
                risk_profile="controlled",
            ),
            SpecialistAgent(
                id="infra_exposure",
                name="InfrastructureExposureAgent",
                team=TeamName.CLOUD_INFRA_TEAM,
                capabilities=["database_port_exposure", "redis_unauthenticated", "elasticsearch_unauth", "memcached_exposure"],
                required_skills=["infrastructure-exposure"],
                preferred_tools=["nmap", "http-client"],
                resource_class=ResourceClass.NETWORK.value,
                risk_profile="controlled",
            ),

            # -------------------------------------------------------------
            # 7. ARTIFACT & SOURCE TEAM
            # -------------------------------------------------------------
            SpecialistAgent(
                id="artifact",
                name="ArtifactAgent",
                team=TeamName.ARTIFACT_SOURCE_TEAM,
                capabilities=["sql_dump_ast_parsing", "csv_export_redaction", "log_file_analysis", "archive_unpacking"],
                required_skills=["artifact-analysis"],
                preferred_tools=["http-client"],
                resource_class=ResourceClass.DISCOVERY.value,
                risk_profile="safe",
            ),
            SpecialistAgent(
                id="secrets",
                name="SecretsAgent",
                team=TeamName.ARTIFACT_SOURCE_TEAM,
                capabilities=["api_key_regex_trufflehog", "private_key_detection", "env_secret_extraction", "jwt_secret_harvest"],
                required_skills=["secret-detection"],
                preferred_tools=["trufflehog", "gitleaks"],
                resource_class=ResourceClass.DISCOVERY.value,
                risk_profile="safe",
            ),
            SpecialistAgent(
                id="source_code",
                name="SourceCodeAgent",
                team=TeamName.ARTIFACT_SOURCE_TEAM,
                capabilities=["git_exposure_dump", "svn_exposure_check", "source_map_endpoint_reconstruct"],
                required_skills=["source-code-recovery"],
                preferred_tools=["git-dumper", "http-client"],
                resource_class=ResourceClass.DISCOVERY.value,
                risk_profile="controlled",
            ),
            SpecialistAgent(
                id="dependency",
                name="DependencyAgent",
                team=TeamName.ARTIFACT_SOURCE_TEAM,
                capabilities=["package_json_analysis", "requirements_txt_audit", "pom_xml_cve_lookup"],
                required_skills=["dependency-analysis"],
                preferred_tools=["osv-scanner", "trivy"],
                resource_class=ResourceClass.INTELLIGENCE.value,
                risk_profile="safe",
            ),
            SpecialistAgent(
                id="supply_chain",
                name="SupplyChainAgent",
                team=TeamName.ARTIFACT_SOURCE_TEAM,
                capabilities=["ci_cd_exposure", "package_typosquatting_check", "build_artifact_intel"],
                required_skills=["supply-chain-security"],
                preferred_tools=["http-client"],
                resource_class=ResourceClass.INTELLIGENCE.value,
                risk_profile="safe",
            ),

            # -------------------------------------------------------------
            # 8. INTELLIGENCE TEAM
            # -------------------------------------------------------------
            SpecialistAgent(
                id="technology",
                name="TechnologyAgent",
                team=TeamName.INTELLIGENCE_TEAM,
                capabilities=["technology_fingerprint", "wappalyzer_heuristics", "cms_detection", "framework_versioning"],
                required_skills=["technology-fingerprinting"],
                preferred_tools=["wappalyzer", "httpx"],
                resource_class=ResourceClass.INTELLIGENCE.value,
                risk_profile="safe",
            ),
            SpecialistAgent(
                id="cve",
                name="CVEAgent",
                team=TeamName.INTELLIGENCE_TEAM,
                capabilities=["cve_applicability_correlation", "cve_kev_lookup", "cve_exploit_db_check", "epss_scoring"],
                required_skills=["cve-research"],
                preferred_tools=["cve-search"],
                resource_class=ResourceClass.INTELLIGENCE.value,
                risk_profile="safe",
            ),
            SpecialistAgent(
                id="threat_intel",
                name="ThreatIntelAgent",
                team=TeamName.INTELLIGENCE_TEAM,
                capabilities=["asn_threat_reputation", "threat_feed_correlation", "malicious_ip_lookup"],
                required_skills=["threat-intelligence"],
                preferred_tools=["alienvault-otx", "shodan"],
                resource_class=ResourceClass.INTELLIGENCE.value,
                risk_profile="safe",
            ),
            SpecialistAgent(
                id="framework_mapping",
                name="FrameworkMappingAgent",
                team=TeamName.INTELLIGENCE_TEAM,
                capabilities=["mitre_attack_mapping", "owasp_top10_mapping", "cwe_classification"],
                required_skills=["framework-mapping"],
                preferred_tools=["mitre-navigator"],
                resource_class=ResourceClass.INTELLIGENCE.value,
                risk_profile="safe",
            ),

            # -------------------------------------------------------------
            # 9. ADVERSARY SIMULATION TEAM
            # -------------------------------------------------------------
            SpecialistAgent(
                id="attack_path",
                name="AttackPathAgent",
                team=TeamName.RED_TEAM,
                capabilities=["attack_path_graph_traversal", "precondition_chain_analysis", "path_feasibility_ranking"],
                required_skills=["attack-path-analysis"],
                preferred_tools=["graph-engine"],
                resource_class=ResourceClass.AI.value,
                risk_profile="controlled",
            ),
            SpecialistAgent(
                id="adversary_sim",
                name="AdversarySimulationAgent",
                team=TeamName.RED_TEAM,
                capabilities=["adversary_simulation", "chained_exploit_simulation", "lateral_movement_modeling"],
                required_skills=["adversary-emulation", "lateral-movement"],
                preferred_tools=["adversary-lab", "http-client"],
                resource_class=ResourceClass.VALIDATION.value,
                risk_profile="aggressive",
            ),
            SpecialistAgent(
                id="priv_esc",
                name="PrivilegeEscalationAgent",
                team=TeamName.RED_TEAM,
                capabilities=["deep_privilege_escalation", "rbac_matrix_violation", "jwt_role_tampering_proof"],
                required_skills=["privilege-escalation"],
                preferred_tools=["http-client"],
                resource_class=ResourceClass.VALIDATION.value,
                risk_profile="aggressive",
            ),
            SpecialistAgent(
                id="cred_reuse",
                name="CredentialReuseAgent",
                team=TeamName.RED_TEAM,
                capabilities=["credential_correlation", "credential_stuffing_emulation", "identity_mapping"],
                required_skills=["credential-reuse"],
                preferred_tools=["http-client"],
                resource_class=ResourceClass.VALIDATION.value,
                risk_profile="controlled",
            ),
            SpecialistAgent(
                id="controlled_exploit",
                name="ControlledExploitAgent",
                team=TeamName.RED_TEAM,
                capabilities=["rce_sandbox_proof", "lfi_proc_self_environ_proof", "canary_read_proof"],
                required_skills=["controlled-exploitation"],
                preferred_tools=["http-client"],
                resource_class=ResourceClass.VALIDATION.value,
                risk_profile="aggressive",
            ),
            SpecialistAgent(
                id="bypass_evasion",
                name="BypassAndFilterEvasionAgent",
                team=TeamName.RED_TEAM,
                capabilities=["waf_bypass_mutation", "unicode_normalization_bypass", "payload_encoding_evasion"],
                required_skills=["waf-bypass"],
                preferred_tools=["http-client"],
                resource_class=ResourceClass.VALIDATION.value,
                risk_profile="aggressive",
            ),

            # -------------------------------------------------------------
            # 10. EVIDENCE TEAM
            # -------------------------------------------------------------
            SpecialistAgent(
                id="evidence",
                name="EvidenceAgent",
                team=TeamName.EVIDENCE_TEAM,
                capabilities=["evidence_capture", "sha256_hashing", "cryptographic_provenance", "raw_wire_logging"],
                required_skills=["evidence-collection"],
                preferred_tools=["evidence-builder"],
                resource_class=ResourceClass.EVIDENCE.value,
                risk_profile="safe",
            ),
            SpecialistAgent(
                id="evidence_critic",
                name="EvidenceCriticAgent",
                team=TeamName.EVIDENCE_TEAM,
                capabilities=["12_step_quality_gate", "false_positive_filtering", "reproducibility_check"],
                required_skills=["evidence-critic"],
                preferred_tools=["quality-gate"],
                resource_class=ResourceClass.EVIDENCE.value,
                risk_profile="safe",
            ),
            SpecialistAgent(
                id="visual_proof",
                name="VisualProofAgent",
                team=TeamName.EVIDENCE_TEAM,
                capabilities=["screenshot_capture", "visual_proof_gallery", "authenticated_page_render"],
                required_skills=["visual-proof"],
                preferred_tools=["playwright", "puppeteer"],
                resource_class=ResourceClass.BROWSER.value,
                risk_profile="safe",
            ),
            SpecialistAgent(
                id="poc",
                name="PoCAgent",
                team=TeamName.EVIDENCE_TEAM,
                capabilities=["curl_poc_generator", "python_reproduction_script_generator", "httpie_command_compiler"],
                required_skills=["poc-compilation"],
                preferred_tools=["poc-compiler"],
                resource_class=ResourceClass.EVIDENCE.value,
                risk_profile="safe",
            ),
            SpecialistAgent(
                id="evidence_sanitizer",
                name="EvidenceSanitizationAgent",
                team=TeamName.EVIDENCE_TEAM,
                capabilities=["credential_redaction", "pii_masking", "token_masking"],
                required_skills=["data-sanitization"],
                preferred_tools=["sanitizer"],
                resource_class=ResourceClass.EVIDENCE.value,
                risk_profile="safe",
            ),

            # -------------------------------------------------------------
            # 11. REPORTING TEAM
            # -------------------------------------------------------------
            SpecialistAgent(
                id="report",
                name="ReportAgent",
                team=TeamName.REPORTING_TEAM,
                capabilities=["hackerone_markdown_export", "pdf_dossier_generator", "executive_summary_compiler", "cvss_v31_calculator"],
                required_skills=["report-generation"],
                preferred_tools=["report-generator", "pdfkit"],
                resource_class=ResourceClass.REPORTING.value,
                risk_profile="safe",
            ),
            SpecialistAgent(
                id="retest",
                name="RetestAgent",
                team=TeamName.REPORTING_TEAM,
                capabilities=["1_click_retest_executor", "before_after_diff_comparison", "remediation_verifier"],
                required_skills=["retest-verification"],
                preferred_tools=["http-client"],
                resource_class=ResourceClass.REPORTING.value,
                risk_profile="controlled",
            ),
            SpecialistAgent(
                id="remediation",
                name="RemediationAgent",
                team=TeamName.REPORTING_TEAM,
                capabilities=["patch_recommendation", "secure_code_generator", "remediation_playbook_builder"],
                required_skills=["remediation-guidance"],
                preferred_tools=["remediation-engine"],
                resource_class=ResourceClass.REPORTING.value,
                risk_profile="safe",
            ),
        ]

        for s in specialists:
            self.agents[s.id] = s
            self.agents[s.name] = s

    def get_agent(self, agent_id_or_name: str) -> Optional[SpecialistAgent]:
        """Retrieves specialist agent by ID or Name."""
        return self.agents.get(agent_id_or_name)

    def find_agents_by_capability(self, capability: str) -> List[SpecialistAgent]:
        """Finds all agents possessing a specific capability."""
        cap_lower = capability.lower().replace("-", "_")
        matched: List[SpecialistAgent] = []
        seen: Set[str] = set()

        for a in self.agents.values():
            if a.id in seen:
                continue
            for c in a.capabilities:
                if cap_lower in c.lower() or c.lower() in cap_lower:
                    matched.append(a)
                    seen.add(a.id)
                    break
        return matched

    def find_agents_by_skill(self, skill_name: str) -> List[SpecialistAgent]:
        """Finds agents requiring or specialized in a skill."""
        s_lower = skill_name.lower().replace("_", "-")
        matched: List[SpecialistAgent] = []
        seen: Set[str] = set()

        for a in self.agents.values():
            if a.id in seen:
                continue
            for s in a.required_skills:
                if s_lower in s.lower() or s.lower() in s_lower:
                    matched.append(a)
                    seen.add(a.id)
                    break
        return matched

    def find_agent_for_capability(self, capability_or_name: str) -> Optional[SpecialistAgent]:
        """Returns best matching specialist agent."""
        if capability_or_name in self.agents:
            return self.agents[capability_or_name]
        matches = self.find_agents_by_capability(capability_or_name)
        return matches[0] if matches else None

    def get_teams_summary(self) -> Dict[str, Any]:
        """Returns structured hierarchy of all 12 teams and their specialist agents."""
        teams_map: Dict[str, List[Dict[str, Any]]] = {}
        seen_ids: Set[str] = set()

        for agent in self.agents.values():
            if agent.id in seen_ids:
                continue
            seen_ids.add(agent.id)

            team_name = agent.team.value
            if team_name not in teams_map:
                teams_map[team_name] = []
            teams_map[team_name].append(agent.to_dict())

        return {
            "total_teams": len(teams_map),
            "total_specialists": len(seen_ids),
            "teams": teams_map,
        }

    def can_claim_task(self, agent_id_or_name: str, capability: str = "") -> bool:
        """Checks if a specialist agent can accept a task."""
        agent = self.get_agent(agent_id_or_name)
        if not agent:
            return False
        return len(agent.active_tasks) < agent.max_concurrency

    def claim_task(self, agent_id_or_name: str, task_id: str) -> bool:
        """Claims a task for a specialist agent if within concurrency limit."""
        agent = self.get_agent(agent_id_or_name)
        if not agent:
            return False
        if len(agent.active_tasks) >= agent.max_concurrency:
            logger.warning("Agent %s at max concurrency (%d)", agent.name, agent.max_concurrency)
            return False
        agent.active_tasks.append(task_id)
        return True

    def release_task(self, agent_id_or_name: str, task_id: str) -> None:
        """Releases a finished task from an agent."""
        agent = self.get_agent(agent_id_or_name)
        if agent and task_id in agent.active_tasks:
            agent.active_tasks.remove(task_id)


team_manager = TeamManager()
