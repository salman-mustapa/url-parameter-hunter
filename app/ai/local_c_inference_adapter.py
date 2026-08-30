"""Local C-Inspired Lightweight Inference Adapter.

Inspired by pure C99 sparse inference engines (e.g. kimi-k3-in-c by Fareed Khan):
- Designed for air-gapped / offline pentest scenarios with zero cloud API dependencies.
- Memory-efficient streaming architecture: operates on low-resource CPU environments.
- Sparse expert activation: selects domain-specific expert heuristics (Recon Expert, Web/API Expert,
  Auth/Crypto Expert, Injection Expert) dynamically based on target surface.
- Formulates structured hypotheses and multi-step attack plans deterministically and rapidly.
"""

from __future__ import annotations

import logging
import os
import shutil
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger("ai.local_c_inference")


@dataclass
class SparseExpert:
    """Specialized domain heuristic expert."""
    expert_id: str
    name: str
    focus_domain: str
    confidence_weight: float


class LocalCInferenceAdapter:
    """Lightweight Local MoE Inference Engine for Offline Pentest Intelligence."""

    def __init__(self) -> None:
        self.binary_path: Optional[str] = shutil.which("kimi_engine") or shutil.which("local_llm")
        self.experts: Dict[str, SparseExpert] = {
            "exp_injection": SparseExpert("exp_injection", "SQLi/XSS/Command Injection Expert", "injection", 0.90),
            "exp_auth": SparseExpert("exp_auth", "Broken Access Control & Auth Expert", "auth", 0.88),
            "exp_exposure": SparseExpert("exp_exposure", "Sensitive Secrets & Git/Config Leak Expert", "exposure", 0.95),
            "exp_network": SparseExpert("exp_network", "Exposed Port & Service Banner Expert", "network", 0.85),
            "exp_api": SparseExpert("exp_api", "API Parameter & IDOR Routing Expert", "api", 0.87),
        }

    async def generate_offline_hypotheses(
        self,
        target_domain: str,
        assets: List[Dict[str, Any]],
        endpoints: List[Dict[str, Any]],
        technologies: List[Dict[str, Any]],
        ports: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Synthesizes structured attack hypotheses using sparse domain routing."""
        hypotheses: List[Dict[str, Any]] = []

        # 1. Evaluate Port & Service Surface (exp_network)
        open_ports = [p.get("port") or p.get("port_number") for p in ports if p]
        high_risk_ports = {8080, 8443, 8000, 9000, 3000, 5000, 27017, 6379, 9200, 445, 3389}
        detected_high_risk = [p for p in open_ports if p in high_risk_ports]

        if detected_high_risk:
            hypotheses.append({
                "statement": f"Non-standard service exposure on ports {detected_high_risk} may allow unauthenticated administrative or internal API access.",
                "target_endpoint": f"http://{target_domain}:{detected_high_risk[0]}",
                "confidence": 0.88,
                "next_test": "nuclei",
                "tool_sequence": ["nuclei", "http_probe"],
                "attack_plan_title": f"Verify Administrative Exposure on Port {detected_high_risk[0]}",
                "expected_result": "Direct HTTP response from administrative dashboard without session token",
            })

        # 2. Evaluate Technology & Framework Signatures (exp_exposure & exp_injection)
        tech_names = [str(t.get("name", "")).lower() for t in technologies if t]
        if any("php" in t or "wordpress" in t or "laravel" in t for t in tech_names):
            hypotheses.append({
                "statement": f"PHP/CMS tech stack on {target_domain} may expose configuration backup files (.env, wp-config.php.bak, dump.sql).",
                "target_endpoint": f"https://{target_domain}/.env",
                "confidence": 0.92,
                "next_test": "sensitive_files",
                "tool_sequence": ["nuclei", "sensitive_files"],
                "attack_plan_title": "Audit Sensitive Environment Secrets (.env / DB Dumps)",
                "expected_result": "HTTP 200 with database credentials or secret keys",
            })

        # 3. Evaluate Endpoints & Parameter Attack Surface (exp_api & exp_auth)
        for ep in endpoints[:10]:
            url = ep.get("url") or ep.get("path") or ""
            if any(param in url for param in ("id=", "user_id=", "account=", "doc_id=", "order=")):
                hypotheses.append({
                    "statement": f"Object identifier parameter in endpoint '{url[:40]}' may be vulnerable to BOLA / IDOR access control bypass.",
                    "target_endpoint": url,
                    "confidence": 0.86,
                    "next_test": "auth_bypass_validator",
                    "tool_sequence": ["auth_bypass_validator", "dalfox"],
                    "attack_plan_title": f"BOLA/IDOR Access Control Validation on {url[:30]}",
                    "expected_result": "Access to unauthorized record with altered user ID",
                })
                break
            elif any(param in url for param in ("redirect=", "url=", "next=", "dest=", "return=")):
                hypotheses.append({
                    "statement": f"Redirection parameter in endpoint '{url[:40]}' may facilitate Open Redirect or SSRF.",
                    "target_endpoint": url,
                    "confidence": 0.84,
                    "next_test": "ssrf_validator",
                    "tool_sequence": ["ssrf_validator", "nuclei"],
                    "attack_plan_title": f"Open Redirect & SSRF Probe on {url[:30]}",
                    "expected_result": "HTTP 302 redirecting to out-of-band canary destination",
                })
                break

        # Fallback general attack surface hypothesis if surface is minimal
        if not hypotheses:
            hypotheses.append({
                "statement": f"Attack surface on {target_domain} may harbor known CVE exposures or security header misconfigurations.",
                "target_endpoint": f"https://{target_domain}",
                "confidence": 0.80,
                "next_test": "nuclei",
                "tool_sequence": ["nuclei", "dalfox"],
                "attack_plan_title": f"CVE & Misconfiguration Sweep on {target_domain}",
                "expected_result": "Vulnerability signature match from security template cluster",
            })

        return hypotheses


local_c_inference = LocalCInferenceAdapter()
