"""Parameter-Centric Semantic Classifier & Hypothesis Engine (V15 Discovery).

Classifies discovered parameters into functional and vulnerability categories:
- IDENTIFIER -> IDOR / BOLA / Broken Function Level Auth
- FILE_PATH -> Path Traversal / LFI / File Inclusion
- URL_REDIRECT -> SSRF / Open Redirect
- QUERY_SEARCH -> XSS / SQLi / SSTI
- COMMAND_EXEC -> Command Injection / RCE
- PRIVILEGE_ROLE -> Privilege Escalation / Mass Assignment
- SECURITY_TOKEN -> Authentication Bypass / Token Leakage / Weak Hash
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from app.orchestration.attack_opportunity import AttackOpportunity, OpportunityState

logger = logging.getLogger("discovery.parameter_classifier")


class ParameterCategory(str, Enum):
    IDENTIFIER = "IDENTIFIER"
    FILE_PATH = "FILE_PATH"
    URL_REDIRECT = "URL_REDIRECT"
    QUERY_SEARCH = "QUERY_SEARCH"
    COMMAND_EXEC = "COMMAND_EXEC"
    PRIVILEGE_ROLE = "PRIVILEGE_ROLE"
    SECURITY_TOKEN = "SECURITY_TOKEN"
    DATA_INPUT = "DATA_INPUT"
    UNKNOWN = "UNKNOWN"


CATEGORY_PATTERNS = {
    ParameterCategory.IDENTIFIER: [
        r"^(id|user_?id|account_?id|uid|order_?id|doc_?id|profile_?id|org_?id|customer_?id|client_?id|item_?id|post_?id|member_?id|invoice_?id|tx_?id|transaction_?id|payment_?id|uuid|guid)$",
        r".*_id$",
        r"^id_.*",
    ],
    ParameterCategory.FILE_PATH: [
        r"^(file|path|doc|folder|root|template|include|page|filepath|filename|dir|uri|document|layout|view|source|read|load|module|conf|config)$",
        r".*(file|path|filename|filepath|template|include|folder)$",
        r"^(file|path|doc|folder|template|include|page)_.*",
    ],
    ParameterCategory.URL_REDIRECT: [
        r"^(url|redirect|next|return|callback|dest|forward|to|target|out|link|goto|ref|continue|feed|host|domain|site|relay|proxy)$",
        r".*(redirect|callback|return_to|next_url|redirect_uri|target_url|dest_url)$",
        r"^(url|redirect|callback|dest|forward|return)_.*",
    ],
    ParameterCategory.QUERY_SEARCH: [
        r"^(q|query|search|filter|find|keyword|term|text|s|match|lookup|tag|category|sort|order_by)$",
        r".*(search|query|filter|keyword|lookup)$",
    ],
    ParameterCategory.COMMAND_EXEC: [
        r"^(cmd|exec|command|run|daemon|ping|eval|process|cli|shell|do|code|script|test|ip|host)$",
        r".*(cmd|exec|command|daemon|shell|ping|eval|process)$",
        r"^(cmd|exec|command|daemon|shell)_.*",
    ],
    ParameterCategory.PRIVILEGE_ROLE: [
        r"^(role|admin|group|permission|level|access|privilege|is_admin|auth_level|scope|super|is_staff)$",
        r".*(role|admin|permission|privilege|auth_level)$",
    ],
    ParameterCategory.SECURITY_TOKEN: [
        r"^(token|key|secret|jwt|api_?key|auth|signature|hash|salt|session|apikey|access_token|refresh_token|bearer)$",
        r".*(token|secret|key|jwt|apikey|bearer|signature)$",
    ],
}


@dataclass
class ParameterClassificationResult:
    parameter_name: str
    category: ParameterCategory
    confidence: float
    recommended_attacks: List[str]
    priority_score: int  # 0 to 100
    hypothesis_template: str


class ParameterClassifier:
    """Classifies parameters by semantics and generates targeted attack opportunities."""

    def classify_parameter(
        self,
        parameter_name: str,
        sample_value: Optional[str] = None,
    ) -> ParameterClassificationResult:
        """Determines category and recommended attacks for a given parameter."""
        clean_name = parameter_name.lower().strip()
        val_str = str(sample_value or "").lower()

        # Check against regex definitions
        for category, patterns in CATEGORY_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, clean_name):
                    return self._build_result(clean_name, category, sample_value)

        # Value-based heuristics
        if sample_value:
            if re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", val_str):
                return self._build_result(clean_name, ParameterCategory.IDENTIFIER, sample_value)
            if val_str.startswith("http://") or val_str.startswith("https://") or "/" in val_str:
                if "/" in val_str and "." in val_str and not val_str.startswith("http"):
                    return self._build_result(clean_name, ParameterCategory.FILE_PATH, sample_value)
                return self._build_result(clean_name, ParameterCategory.URL_REDIRECT, sample_value)
            if re.match(r"^[0-9]+$", val_str) and len(val_str) <= 10:
                return self._build_result(clean_name, ParameterCategory.IDENTIFIER, sample_value)

        # Default fallback
        return ParameterClassificationResult(
            parameter_name=clean_name,
            category=ParameterCategory.DATA_INPUT,
            confidence=0.5,
            recommended_attacks=["xss", "sqli"],
            priority_score=50,
            hypothesis_template="Input field may be vulnerable to XSS or SQL Injection",
        )

    def _build_result(
        self,
        param: str,
        category: ParameterCategory,
        sample_value: Optional[str],
    ) -> ParameterClassificationResult:
        if category == ParameterCategory.IDENTIFIER:
            return ParameterClassificationResult(
                parameter_name=param,
                category=category,
                confidence=0.9,
                recommended_attacks=["idor", "sqli"],
                priority_score=90,
                hypothesis_template=f"Numeric/UUID identifier '{param}' exposes horizontal or vertical object references (IDOR/BOLA).",
            )
        elif category == ParameterCategory.FILE_PATH:
            return ParameterClassificationResult(
                parameter_name=param,
                category=category,
                confidence=0.92,
                recommended_attacks=["traversal", "ssrf"],
                priority_score=92,
                hypothesis_template=f"Path parameter '{param}' accepts system path traversals or local file inclusions.",
            )
        elif category == ParameterCategory.URL_REDIRECT:
            return ParameterClassificationResult(
                parameter_name=param,
                category=category,
                confidence=0.88,
                recommended_attacks=["ssrf", "open_redirect"],
                priority_score=85,
                hypothesis_template=f"Redirect/Callback parameter '{param}' permits Server-Side Request Forgery or Open Redirection.",
            )
        elif category == ParameterCategory.QUERY_SEARCH:
            return ParameterClassificationResult(
                parameter_name=param,
                category=category,
                confidence=0.85,
                recommended_attacks=["xss", "sqli", "ssti"],
                priority_score=75,
                hypothesis_template=f"Search/Filter query parameter '{param}' is vulnerable to reflected XSS, SQLi, or Template Injection.",
            )
        elif category == ParameterCategory.COMMAND_EXEC:
            return ParameterClassificationResult(
                parameter_name=param,
                category=category,
                confidence=0.95,
                recommended_attacks=["rce", "sqli"],
                priority_score=98,
                hypothesis_template=f"System execution parameter '{param}' allows arbitrary OS command execution (RCE).",
            )
        elif category == ParameterCategory.PRIVILEGE_ROLE:
            return ParameterClassificationResult(
                parameter_name=param,
                category=category,
                confidence=0.87,
                recommended_attacks=["auth", "idor"],
                priority_score=88,
                hypothesis_template=f"Role/Permission parameter '{param}' can be tampered with for privilege escalation.",
            )
        elif category == ParameterCategory.SECURITY_TOKEN:
            return ParameterClassificationResult(
                parameter_name=param,
                category=category,
                confidence=0.90,
                recommended_attacks=["auth"],
                priority_score=85,
                hypothesis_template=f"Security token '{param}' may suffer from weak entropy or broken verification.",
            )
        else:
            return ParameterClassificationResult(
                parameter_name=param,
                category=ParameterCategory.UNKNOWN,
                confidence=0.4,
                recommended_attacks=["xss", "sqli"],
                priority_score=45,
                hypothesis_template=f"Generic parameter '{param}' fuzzed for injection flaws.",
            )

    def generate_hypotheses_for_url(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        method: str = "GET",
        technology: Optional[str] = None,
    ) -> List[AttackOpportunity]:
        """Generates concrete AttackOpportunity objects for a given endpoint and parameters."""
        opportunities: List[AttackOpportunity] = []
        parsed = urlparse(url)
        all_params: Dict[str, Any] = {}

        # Extract query parameters from URL
        if parsed.query:
            for k, v in parse_qs(parsed.query).items():
                all_params[k] = v[0] if v else ""

        if params:
            all_params.update(params)

        for param_name, sample_val in all_params.items():
            classification = self.classify_parameter(param_name, str(sample_val))
            for attack in classification.recommended_attacks:
                opp = AttackOpportunity(
                    target=f"{parsed.scheme}://{parsed.netloc}",
                    endpoint=url,
                    protocol=parsed.scheme or "http",
                    service="http",
                    technology=technology,
                    parameter=param_name,
                    hypothesis=classification.hypothesis_template,
                    attack_type=attack,
                    confidence=classification.confidence,
                    priority=classification.priority_score,
                    state=OpportunityState.DISCOVERED,
                    metadata={
                        "category": classification.category.value,
                        "method": method,
                        "sample_value": sample_val,
                    },
                )
                opportunities.append(opp)

        return opportunities


parameter_classifier = ParameterClassifier()
