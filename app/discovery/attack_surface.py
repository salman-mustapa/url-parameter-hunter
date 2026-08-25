"""Application Attack-Surface Agent & Endpoint Tree Modeler (Pentest Spec §3, §4).

Builds a comprehensive, hierarchical application attack-surface model:
- Authentication (Login, Register, Password Reset, MFA)
- API Routes (REST, GraphQL, WebSocket, SOAP)
- Files (Upload, Download, Static Assets)
- Search & Data Operations (Search, Filter, Sort, Pagination)
- Administration (Admin Portals, Dashboards, Internal Tools)
- Parameter & Token Discovery (Query, Body, JSON, Headers, Cookies, JWT, OAuth, CSRF)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger("discovery.attack_surface")


class EndpointCategory(str, Enum):
    AUTHENTICATION = "Authentication"
    API = "API"
    FILES = "Files"
    SEARCH_DATA = "Search & Data"
    ADMINISTRATION = "Administration"
    GENERAL_WEB = "General Web"


class ParameterLocation(str, Enum):
    QUERY = "query"
    BODY = "body"
    JSON = "json"
    HEADER = "header"
    COOKIE = "cookie"
    MULTIPART = "multipart"


@dataclass
class DiscoveredParameter:
    name: str
    location: ParameterLocation
    sample_value: Optional[str] = None
    is_sensitive: bool = False
    inferred_type: str = "string"  # integer, string, boolean, object_id, uuid, token

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "location": self.location.value,
            "sample_value": self.sample_value,
            "is_sensitive": self.is_sensitive,
            "inferred_type": self.inferred_type,
        }


@dataclass
class ModeledEndpoint:
    url: str
    method: str
    category: EndpointCategory
    subcategory: str
    parameters: List[DiscoveredParameter] = field(default_factory=list)
    auth_required: bool = False
    auth_type: Optional[str] = None  # Session, JWT, OAuth, Basic, None
    has_csrf_protection: bool = False
    content_type: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "category": self.category.value,
            "subcategory": self.subcategory,
            "parameters": [p.to_dict() for p in self.parameters],
            "auth_required": self.auth_required,
            "auth_type": self.auth_type,
            "has_csrf_protection": self.has_csrf_protection,
            "content_type": self.content_type,
        }


@dataclass
class ApplicationAttackSurfaceModel:
    target_root: str
    endpoints: List[ModeledEndpoint] = field(default_factory=list)
    auth_endpoints: List[ModeledEndpoint] = field(default_factory=list)
    api_endpoints: List[ModeledEndpoint] = field(default_factory=list)
    file_endpoints: List[ModeledEndpoint] = field(default_factory=list)
    search_endpoints: List[ModeledEndpoint] = field(default_factory=list)
    admin_endpoints: List[ModeledEndpoint] = field(default_factory=list)
    discovered_parameters: Set[str] = field(default_factory=set)
    identified_auth_mechanisms: Set[str] = field(default_factory=set)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_root": self.target_root,
            "total_endpoints": len(self.endpoints),
            "authentication": [e.to_dict() for e in self.auth_endpoints],
            "api": [e.to_dict() for e in self.api_endpoints],
            "files": [e.to_dict() for e in self.file_endpoints],
            "search_data": [e.to_dict() for e in self.search_endpoints],
            "administration": [e.to_dict() for e in self.admin_endpoints],
            "discovered_parameters_count": len(self.discovered_parameters),
            "identified_auth_mechanisms": list(self.identified_auth_mechanisms),
        }


class ApplicationAttackSurfaceAgent:
    """Classifies endpoints and maps the structured application attack surface."""

    SENSITIVE_PARAM_NAMES = {
        "password", "pass", "pwd", "secret", "token", "auth", "key",
        "api_key", "session", "jwt", "bearer", "credit_card", "ssn"
    }

    OBJECT_ID_PARAM_NAMES = {
        "id", "user_id", "userid", "account_id", "uuid", "doc_id", "order_id", "item_id"
    }

    def __init__(self) -> None:
        pass

    def build_surface_model(
        self,
        target_root: str,
        urls: List[str],
        additional_metadata: Optional[List[Dict[str, Any]]] = None,
    ) -> ApplicationAttackSurfaceModel:
        """Analyzes a list of URLs and builds the hierarchical attack surface model."""
        model = ApplicationAttackSurfaceModel(target_root=target_root)
        meta_by_url: Dict[str, Dict[str, Any]] = {}
        if additional_metadata:
            for item in additional_metadata:
                if "url" in item:
                    meta_by_url[item["url"]] = item

        for url in urls:
            meta = meta_by_url.get(url, {})
            modeled = self.classify_endpoint(url, meta)
            model.endpoints.append(modeled)

            # Route into hierarchical buckets
            if modeled.category == EndpointCategory.AUTHENTICATION:
                model.auth_endpoints.append(modeled)
            elif modeled.category == EndpointCategory.API:
                model.api_endpoints.append(modeled)
            elif modeled.category == EndpointCategory.FILES:
                model.file_endpoints.append(modeled)
            elif modeled.category == EndpointCategory.SEARCH_DATA:
                model.search_endpoints.append(modeled)
            elif modeled.category == EndpointCategory.ADMINISTRATION:
                model.admin_endpoints.append(modeled)

            for p in modeled.parameters:
                model.discovered_parameters.add(p.name)

            if modeled.auth_type:
                model.identified_auth_mechanisms.add(modeled.auth_type)

        return model

    def classify_endpoint(self, url: str, metadata: Optional[Dict[str, Any]] = None) -> ModeledEndpoint:
        """Determines the Category, Subcategory, and Parameters of a single endpoint."""
        meta = metadata or {}
        parsed = urlparse(url)
        path = parsed.path.lower()
        method = meta.get("method", "GET").upper()

        category = EndpointCategory.GENERAL_WEB
        subcategory = "General Page"
        auth_type: Optional[str] = None
        auth_required = False

        # 1. Authentication
        if any(k in path for k in ("/login", "/signin", "/auth/login", "/session/new", "/authenticate")):
            category = EndpointCategory.AUTHENTICATION
            subcategory = "Login"
            auth_type = "Session/Password"
        elif any(k in path for k in ("/register", "/signup", "/join", "/create-account")):
            category = EndpointCategory.AUTHENTICATION
            subcategory = "Registration"
        elif any(k in path for k in ("/reset-password", "/forgot-password", "/recovery", "/password/reset")):
            category = EndpointCategory.AUTHENTICATION
            subcategory = "Password Reset"
        elif any(k in path for k in ("/mfa", "/2fa", "/otp", "/verify-code")):
            category = EndpointCategory.AUTHENTICATION
            subcategory = "MFA Verification"

        # 2. Administration
        elif any(k in path for k in ("/admin", "/administrator", "/manage", "/dashboard/admin", "/console", "/portal/admin")):
            category = EndpointCategory.ADMINISTRATION
            subcategory = "Admin Portal"
            auth_required = True

        # 3. API
        elif any(k in path for k in ("/api/", "/rest/", "/v1/", "/v2/", "/v3/", "/graphql", "/ws", "/socket.io")):
            category = EndpointCategory.API
            if "graphql" in path:
                subcategory = "GraphQL Endpoint"
            elif any(k in path for k in ("/ws", "/socket.io")):
                subcategory = "WebSocket"
            else:
                subcategory = "REST API"
            if meta.get("has_jwt") or "bearer" in str(meta.get("headers", {})).lower():
                auth_type = "JWT"
                auth_required = True

        # 4. Files
        elif any(k in path for k in ("/upload", "/files/upload", "/media/upload", "/import", "/export", "/download")):
            category = EndpointCategory.FILES
            subcategory = "File Upload/Download"

        # 5. Search & Data
        elif any(k in path for k in ("/search", "/find", "/filter", "/query", "/catalog", "/products", "/items")):
            category = EndpointCategory.SEARCH_DATA
            subcategory = "Search & Filter"

        # Parse Parameters
        params: List[DiscoveredParameter] = []
        # Query parameters
        if parsed.query:
            qs = parse_qs(parsed.query)
            for k, v in qs.items():
                val = v[0] if v else ""
                inferred = self._infer_param_type(k, val)
                params.append(
                    DiscoveredParameter(
                        name=k,
                        location=ParameterLocation.QUERY,
                        sample_value=val,
                        is_sensitive=k.lower() in self.SENSITIVE_PARAM_NAMES,
                        inferred_type=inferred,
                    )
                )

        # POST / Body parameters from metadata
        body_params = meta.get("body_params") or meta.get("json_params")
        if isinstance(body_params, dict):
            for k, val in body_params.items():
                inferred = self._infer_param_type(k, str(val))
                params.append(
                    DiscoveredParameter(
                        name=k,
                        location=ParameterLocation.JSON if meta.get("content_type") == "application/json" else ParameterLocation.BODY,
                        sample_value=str(val),
                        is_sensitive=k.lower() in self.SENSITIVE_PARAM_NAMES,
                        inferred_type=inferred,
                    )
                )

        return ModeledEndpoint(
            url=url,
            method=method,
            category=category,
            subcategory=subcategory,
            parameters=params,
            auth_required=auth_required,
            auth_type=auth_type,
            has_csrf_protection=meta.get("has_csrf_protection", False),
            content_type=meta.get("content_type"),
        )

    def _infer_param_type(self, name: str, value: str) -> str:
        """Infers the data type and purpose of a parameter."""
        name_lower = name.lower()
        if name_lower in self.OBJECT_ID_PARAM_NAMES or name_lower.endswith("_id"):
            return "object_id"
        if re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", value, re.I):
            return "uuid"
        if value.isdigit():
            return "integer"
        if value.lower() in ("true", "false", "1", "0"):
            return "boolean"
        return "string"


attack_surface_agent = ApplicationAttackSurfaceAgent()
