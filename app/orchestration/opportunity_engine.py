"""Research Opportunity Engine & Opportunity Detector (V10 Orchestration).

Evaluates incoming discoveries, signals, and events in real time:
- "What just changed?"
- "What preconditions are satisfied?"
- "What test or validation task should be spawned immediately?"
- "What priority (0-100) should be assigned?"
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from urllib.parse import parse_qs, urlparse

from app.validation.precondition_engine import PreconditionStatus, precondition_engine

logger = logging.getLogger("orchestration.opportunity_engine")


class OpportunityType(str, Enum):
    IDOR_CANDIDATE = "idor_candidate"
    SQLI_CANDIDATE = "sqli_candidate"
    XSS_CANDIDATE = "xss_candidate"
    SSRF_CANDIDATE = "ssrf_candidate"
    RCE_CANDIDATE = "rce_candidate"
    AUTH_BYPASS_CANDIDATE = "auth_bypass_candidate"
    DEFAULT_CREDENTIALS = "default_credentials"
    ACCESS_CONTROL_403 = "access_control_403"
    SENSITIVE_FILE_EXPOSURE = "sensitive_file_exposure"
    DIRECTORY_LISTING = "directory_listing"
    WORDPRESS_AUDIT = "wordpress_audit"
    FRAMEWORK_CVE = "framework_cve"
    GRAPHQL_INTROSPECTION = "graphql_introspection"
    JWT_MISCONFIG = "jwt_misconfig"
    SSTI_CANDIDATE = "ssti_candidate"
    CREDENTIAL_ESCALATION = "credential_escalation"


@dataclass
class Opportunity:
    opportunity_id: str
    opportunity_type: OpportunityType
    target_url: str
    priority: int  # 0 to 100 (100 = Immediate P0 Fast Path)
    recommended_worker: str  # worker-validation, worker-web, worker-artifact, etc.
    preconditions: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    evidence_source: str = "event_stream"
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "opportunity_id": self.opportunity_id,
            "opportunity_type": self.opportunity_type.value,
            "target_url": self.target_url,
            "priority": self.priority,
            "recommended_worker": self.recommended_worker,
            "preconditions": self.preconditions,
            "context": self.context,
            "evidence_source": self.evidence_source,
            "created_at": self.created_at,
        }


class ResearchOpportunityEngine:
    """Intelligent event analyzer that converts discoveries into prioritized security opportunities."""

    def __init__(self) -> None:
        self._evaluated_cache: Set[str] = set()

    def evaluate_event(self, event_type: str, data: Dict[str, Any]) -> List[Opportunity]:
        """Evaluates an incoming discovery event and produces actionable opportunities."""
        opportunities: List[Opportunity] = []
        clean_ev = event_type.lower()

        # 1. Endpoint & Parameter Discovery
        if "endpoint" in clean_ev or "url.discovered" in clean_ev or "parameter.discovered" in clean_ev:
            opps = self._evaluate_endpoint_event(data)
            opportunities.extend(opps)

        # 2. Technology Discovery
        elif "technology" in clean_ev or "tech" in clean_ev:
            opps = self._evaluate_technology_event(data)
            opportunities.extend(opps)

        # 3. Authentication Form Discovery
        elif "auth.form" in clean_ev or "login" in clean_ev:
            opps = self._evaluate_auth_form_event(data)
            opportunities.extend(opps)

        # 4. Directory Listing Discovery
        elif "directory_listing" in clean_ev:
            opps = self._evaluate_directory_listing_event(data)
            opportunities.extend(opps)

        # 5. Artifact Discovery (SQL Dump / .env / CSV)
        elif "artifact" in clean_ev:
            opps = self._evaluate_artifact_event(data)
            opportunities.extend(opps)

        # 6. 403 Forbidden Response
        elif "403" in clean_ev or data.get("status_code") == 403:
            opps = self._evaluate_403_event(data)
            opportunities.extend(opps)

        return opportunities

    def _evaluate_endpoint_event(self, data: Dict[str, Any]) -> List[Opportunity]:
        url = data.get("url") or data.get("endpoint") or ""
        if not url or url in self._evaluated_cache:
            return []

        opps: List[Opportunity] = []
        parsed = urlparse(url)
        params = data.get("parameters") or []
        
        # Extract query parameters from URL string if not explicitly passed
        if not params and parsed.query:
            qs = parse_qs(parsed.query, keep_blank_values=True)
            params = [{"name": k, "location": "query"} for k in qs.keys()]

        param_names = [p["name"].lower() if isinstance(p, dict) else str(p).lower() for p in params]
        url_lower = url.lower()

        # A. SQL Injection Precondition Check
        if any(kw in url_lower for kw in ["search", "find", "item", "product", "category", "filter", "query", "user", "order", "id="]) or any(p in param_names for p in ["id", "q", "query", "search", "category", "cat", "user", "name", "sort", "filter"]):
            opps.append(Opportunity(
                opportunity_id=f"opp_sqli_{uuid.uuid4().hex[:8]}",
                opportunity_type=OpportunityType.SQLI_CANDIDATE,
                target_url=url,
                priority=98,  # Critical / High-Value Fast Path
                recommended_worker="worker-validation",
                preconditions=["input_reflection_or_db_interaction"],
                context={"url": url, "parameters": params, "test_family": "sql_injection"},
                evidence_source="endpoint_crawler",
            ))

        # B. IDOR / Broken Access Control Precondition Check
        idor_eval = precondition_engine.evaluate("IDOR", {"url": url, "parameters": params})
        if idor_eval.status == PreconditionStatus.SATISFIED or any(p in param_names for p in ["id", "user_id", "uid", "account_id", "order_id", "doc_id", "profile_id", "no"]):
            opps.append(Opportunity(
                opportunity_id=f"opp_idor_{uuid.uuid4().hex[:8]}",
                opportunity_type=OpportunityType.IDOR_CANDIDATE,
                target_url=url,
                priority=92,
                recommended_worker="worker-validation",
                preconditions=["numerical_or_guid_identifier"],
                context={"url": url, "parameters": params, "test_family": "idor"},
                evidence_source="endpoint_crawler",
            ))

        # C. SSRF Precondition Check
        ssrf_eval = precondition_engine.evaluate("SSRF", {"url": url, "parameters": params})
        if ssrf_eval.status == PreconditionStatus.SATISFIED or any(k in pn for pn in param_names for k in ["url", "target", "dest", "redirect", "uri", "feed", "webhook", "host", "endpoint", "path", "src", "domain", "load", "fetch"]):
            opps.append(Opportunity(
                opportunity_id=f"opp_ssrf_{uuid.uuid4().hex[:8]}",
                opportunity_type=OpportunityType.SSRF_CANDIDATE,
                target_url=url,
                priority=90,
                recommended_worker="worker-validation",
                preconditions=["url_or_hostname_parameter"],
                context={"url": url, "parameters": params, "test_family": "ssrf"},
                evidence_source="endpoint_crawler",
            ))

        # D. XSS Precondition Check
        if any(k in pn for pn in param_names for k in ["q", "query", "search", "msg", "message", "keyword", "comment", "title", "text", "body", "desc"]):
            opps.append(Opportunity(
                opportunity_id=f"opp_xss_{uuid.uuid4().hex[:8]}",
                opportunity_type=OpportunityType.XSS_CANDIDATE,
                target_url=url,
                priority=85,
                recommended_worker="worker-validation",
                preconditions=["reflected_string_parameter"],
                context={"url": url, "parameters": params, "test_family": "xss"},
                evidence_source="endpoint_crawler",
            ))

        # E. RCE / Command Injection Precondition Check
        if any(k in pn for pn in param_names for k in ["cmd", "exec", "command", "ping", "host", "ip", "daemon", "eval", "code", "run", "process"]):
            opps.append(Opportunity(
                opportunity_id=f"opp_rce_{uuid.uuid4().hex[:8]}",
                opportunity_type=OpportunityType.RCE_CANDIDATE,
                target_url=url,
                priority=100,  # Top Priority P0
                recommended_worker="worker-validation",
                preconditions=["os_execution_surface"],
                context={"url": url, "parameters": params, "test_family": "rce"},
                evidence_source="endpoint_crawler",
            ))

        return opps

    def _evaluate_technology_event(self, data: Dict[str, Any]) -> List[Opportunity]:
        tech_name = (data.get("name") or data.get("technology") or "").lower()
        version = data.get("version") or ""
        url = data.get("url") or data.get("target") or data.get("host") or ""
        opps: List[Opportunity] = []

        if "wordpress" in tech_name:
            opps.append(Opportunity(
                opportunity_id=f"opp_wp_{uuid.uuid4().hex[:8]}",
                opportunity_type=OpportunityType.WORDPRESS_AUDIT,
                target_url=url,
                priority=88,
                recommended_worker="worker-intelligence",
                preconditions=["wordpress_core_detected"],
                context={"url": url, "technology": "WordPress", "version": version},
                evidence_source="tech_fingerprint",
            ))
        elif "graphql" in tech_name or "/graphql" in url:
            opps.append(Opportunity(
                opportunity_id=f"opp_gql_{uuid.uuid4().hex[:8]}",
                opportunity_type=OpportunityType.GRAPHQL_INTROSPECTION,
                target_url=url,
                priority=85,
                recommended_worker="worker-validation",
                preconditions=["graphql_endpoint_present"],
                context={"url": url, "technology": "GraphQL"},
                evidence_source="tech_fingerprint",
            ))
        elif any(f in tech_name for f in ["laravel", "spring", "django", "next.js", "express", "apache", "nginx"]):
            opps.append(Opportunity(
                opportunity_id=f"opp_cve_{uuid.uuid4().hex[:8]}",
                opportunity_type=OpportunityType.FRAMEWORK_CVE,
                target_url=url,
                priority=80,
                recommended_worker="worker-intelligence",
                preconditions=["framework_fingerprint_identified"],
                context={"url": url, "technology": tech_name, "version": version},
                evidence_source="tech_fingerprint",
            ))

        return opps

    def _evaluate_auth_form_event(self, data: Dict[str, Any]) -> List[Opportunity]:
        url = data.get("url") or ""
        opps: List[Opportunity] = []
        if url:
            opps.append(Opportunity(
                opportunity_id=f"opp_auth_{uuid.uuid4().hex[:8]}",
                opportunity_type=OpportunityType.DEFAULT_CREDENTIALS,
                target_url=url,
                priority=94,
                recommended_worker="worker-validation",
                preconditions=["verified_login_form_present"],
                context={
                    "url": url,
                    "form_action": data.get("form_action", url),
                    "user_field": data.get("username_field", "username"),
                    "pass_field": data.get("password_field", "password"),
                    "test_family": "controlled_authentication_audit",
                },
                evidence_source="auth_form_parser",
            ))
            opps.append(Opportunity(
                opportunity_id=f"opp_auth_bypass_{uuid.uuid4().hex[:8]}",
                opportunity_type=OpportunityType.AUTH_BYPASS_CANDIDATE,
                target_url=url,
                priority=96,
                recommended_worker="worker-validation",
                preconditions=["login_form_input_fields"],
                context={"url": url, "test_family": "sqli_auth_bypass"},
                evidence_source="auth_form_parser",
            ))
        return opps

    def _evaluate_directory_listing_event(self, data: Dict[str, Any]) -> List[Opportunity]:
        url = data.get("url") or ""
        opps: List[Opportunity] = []
        if url:
            opps.append(Opportunity(
                opportunity_id=f"opp_dirlist_{uuid.uuid4().hex[:8]}",
                opportunity_type=OpportunityType.DIRECTORY_LISTING,
                target_url=url,
                priority=95,
                recommended_worker="worker-artifact",
                preconditions=["directory_index_table_exposed"],
                context={"url": url, "file_count": data.get("file_count", 0)},
                evidence_source="directory_listing_parser",
            ))
        return opps

    def _evaluate_artifact_event(self, data: Dict[str, Any]) -> List[Opportunity]:
        file_type = data.get("file_type", "")
        url = data.get("url", "")
        opps: List[Opportunity] = []
        if file_type in ("sql_dump", "backup_sql", "env_file", "csv_export"):
            opps.append(Opportunity(
                opportunity_id=f"opp_escalate_{uuid.uuid4().hex[:8]}",
                opportunity_type=OpportunityType.CREDENTIAL_ESCALATION,
                target_url=url,
                priority=97,
                recommended_worker="worker-intelligence",
                preconditions=["sensitive_artifact_acquired"],
                context={"url": url, "file_type": file_type, "sha256": data.get("sha256")},
                evidence_source="artifact_engine",
            ))
        return opps

    def _evaluate_403_event(self, data: Dict[str, Any]) -> List[Opportunity]:
        url = data.get("url") or ""
        opps: List[Opportunity] = []
        if url:
            opps.append(Opportunity(
                opportunity_id=f"opp_403_{uuid.uuid4().hex[:8]}",
                opportunity_type=OpportunityType.ACCESS_CONTROL_403,
                target_url=url,
                priority=82,
                recommended_worker="worker-validation",
                preconditions=["http_403_forbidden_returned"],
                context={"url": url, "test_family": "403_access_bypass"},
                evidence_source="http_probe",
            ))
        return opps


opportunity_engine = ResearchOpportunityEngine()
