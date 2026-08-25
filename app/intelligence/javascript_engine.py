"""JavaScript & Source-Map Intelligence Engine (§12, §13).

Extracts actionable intelligence from client-side JavaScript files and bundles:
- Hidden REST / GraphQL API endpoints and routes
- Hidden URL and query parameters
- Hardcoded secrets, API tokens, JWTs, cloud credentials
- Internal subdomains, third-party SaaS integrations
- Source-map (.map) indicators and feature flags
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("intelligence.javascript_engine")


@dataclass
class JSIntelligenceResult:
    js_url: str
    discovered_endpoints: List[str] = field(default_factory=list)
    discovered_parameters: List[str] = field(default_factory=list)
    discovered_subdomains: List[str] = field(default_factory=list)
    discovered_secrets: List[Dict[str, Any]] = field(default_factory=list)
    third_party_services: List[str] = field(default_factory=list)
    source_map_urls: List[str] = field(default_factory=list)
    feature_flags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class JavaScriptIntelligenceEngine:
    """Parses and correlates client-side JavaScript intelligence into actionable attack surface nodes."""

    def __init__(self) -> None:
        # Regex for REST API endpoints and routes
        self.endpoint_regex = re.compile(
            r"""(?:["'])(/(?:api|v[0-9]|rest|graphql|admin|auth|user|items|data|app|internal)[a-zA-Z0-9_\-/\.{}]+)(?:["'])""",
            re.IGNORECASE
        )
        
        # Regex for full URL endpoints
        self.url_regex = re.compile(
            r"""(?:https?://[a-zA-Z0-9_\-\.]+)/(?:api|v[0-9]|rest|graphql|admin)[a-zA-Z0-9_\-/\.{}]+""",
            re.IGNORECASE
        )

        # Regex for parameters
        self.param_regex = re.compile(
            r"""(?:params|query|queryParams|params\.add|data|body|formData)\s*[:=]\s*\{([^}]+)\}""",
            re.IGNORECASE
        )
        self.param_key_regex = re.compile(r"""['"]([a-zA-Z0-9_\-]+)['"]\s*:""")

        # Regex for secrets and API keys
        self.secret_patterns = [
            (r"""(?:api[_-]?key|apikey|secret|token|auth[_-]?token)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{16,})['"]""", "API_KEY_OR_TOKEN", "HIGH"),
            (r"""eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*""", "JWT_TOKEN", "MEDIUM"),
            (r"""(?:AIza[0-9A-Za-z-_]{35})""", "GOOGLE_API_KEY", "HIGH"),
            (r"""(?:AKIA[0-9A-Z]{16})""", "AWS_ACCESS_KEY_ID", "CRITICAL"),
            (r"""(?:ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})""", "GITHUB_TOKEN", "CRITICAL"),
            (r"""(?:sk-[a-zA-Z0-9]{32,})""", "OPENAI_OR_STRIPE_KEY", "HIGH"),
            (r"""(?:xox[baprs]-[0-9a-zA-Z]{10,48})""", "SLACK_TOKEN", "HIGH"),
            (r"""(?:sq0atp-[0-9A-Za-z\-_]{22})""", "SQUARE_TOKEN", "HIGH"),
        ]

        # Third-party SaaS services
        self.saas_signatures = {
            "Firebase": r"firebaseio\.com|googleapis\.com/identitytoolkit",
            "AWS S3": r"s3\.amazonaws\.com|\.s3\.[a-z0-9\-]+\.amazonaws\.com",
            "Supabase": r"\.supabase\.co",
            "Stripe": r"js\.stripe\.com|api\.stripe\.com",
            "Cloudinary": r"res\.cloudinary\.com",
            "Auth0": r"\.auth0\.com",
            "SendGrid": r"api\.sendgrid\.com",
            "Algolia": r"\.algolia\.net|\.algolianet\.com",
            "Sentry": r"sentry\.io",
            "Mixpanel": r"api\.mixpanel\.com",
            "Datadog": r"browser-intake-datadoghq\.com"
        }

        # Source map indicator
        self.source_map_regex = re.compile(r"""//#\s*sourceMappingURL=([^\s]+)""")

    def analyze_script(self, js_content: str, js_url: str, base_domain: Optional[str] = None) -> JSIntelligenceResult:
        """Parse JavaScript content and extract all intelligence entities."""
        endpoints: Set[str] = set()
        parameters: Set[str] = set()
        subdomains: Set[str] = set()
        secrets: List[Dict[str, Any]] = []
        third_party: Set[str] = set()
        source_maps: List[str] = []
        feature_flags: Set[str] = set()

        if not js_content:
            return JSIntelligenceResult(js_url=js_url)

        # 1. Extract API Endpoints
        for match in self.endpoint_regex.findall(js_content):
            clean_ep = match.split("?")[0].strip()
            if len(clean_ep) > 3 and not clean_ep.endswith((".png", ".jpg", ".svg", ".css")):
                endpoints.add(clean_ep)

        for match in self.url_regex.findall(js_content):
            endpoints.add(match.strip())

        # 2. Extract Query / Object Parameters
        for block in self.param_regex.findall(js_content):
            keys = self.param_key_regex.findall(block)
            for k in keys:
                if len(k) < 32 and not k.isdigit():
                    parameters.add(k)

        # Direct search for common parameter patterns in fetch/axios
        for param_match in re.findall(r"""[?&]([a-zA-Z0-9_\-]+)=(?:[^&"'\s]+)""", js_content):
            if len(param_match) < 32:
                parameters.add(param_match)

        # 3. Extract Secrets & Credentials
        seen_secrets = set()
        for pat, sec_type, severity in self.secret_patterns:
            matches = re.finditer(pat, js_content)
            for m in matches:
                sec_val = m.group(0) if not m.groups() else m.group(1)
                sec_hash = hash(sec_val)
                if sec_hash not in seen_secrets:
                    seen_secrets.add(sec_hash)
                    # Mask secret value for safe storage
                    masked = sec_val[:4] + "*" * (len(sec_val) - 8) + sec_val[-4:] if len(sec_val) > 10 else "***"
                    secrets.append({
                        "type": sec_type,
                        "severity": severity,
                        "masked_value": masked,
                        "raw_snippet": js_content[max(0, m.start() - 20):min(len(js_content), m.end() + 20)].strip()
                    })

        # 4. Extract Subdomains related to target
        if base_domain:
            subdomain_regex = re.compile(rf"""(?:[a-zA-Z0-9_\-\.]+)\.{re.escape(base_domain)}""", re.IGNORECASE)
            for sub in subdomain_regex.findall(js_content):
                sub_clean = sub.lower().strip(".")
                if sub_clean != base_domain.lower():
                    subdomains.add(sub_clean)

        # 5. Detect Third-Party SaaS Integrations
        for saas_name, pat in self.saas_signatures.items():
            if re.search(pat, js_content, re.IGNORECASE):
                third_party.add(saas_name)

        # 6. Source-Map & Feature Flags
        sm_match = self.source_map_regex.search(js_content)
        if sm_match:
            source_maps.append(sm_match.group(1))

        for flag in re.findall(r"""(?:FEATURE_[A-Z0-9_]+|ENABLE_[A-Z0-9_]+|DEBUG_[A-Z0-9_]+)""", js_content):
            feature_flags.add(flag)

        return JSIntelligenceResult(
            js_url=js_url,
            discovered_endpoints=sorted(list(endpoints)),
            discovered_parameters=sorted(list(parameters)),
            discovered_subdomains=sorted(list(subdomains)),
            discovered_secrets=secrets,
            third_party_services=sorted(list(third_party)),
            source_map_urls=source_maps,
            feature_flags=sorted(list(feature_flags)),
            metadata={
                "file_length_bytes": len(js_content),
                "total_endpoints": len(endpoints),
                "total_parameters": len(parameters),
                "total_secrets": len(secrets)
            }
        )


# Global Singleton Instance
js_intelligence_engine = JavaScriptIntelligenceEngine()
