"""Specialized Vulnerability Validators Package."""

from typing import Dict, Optional

from app.validation.registry import ValidatorRegistry
from app.validation.validators.auth_bypass import AuthBypassValidator, auth_bypass_validator
from app.validation.validators.authorization import AuthorizationValidator, authorization_validator
from app.validation.validators.base import BaseVulnerabilityValidator
from app.validation.validators.cors import CORSValidator, cors_validator
from app.validation.validators.csrf import CSRFValidator, csrf_validator
from app.validation.validators.file_upload import FileUploadValidator, file_upload_validator
from app.validation.validators.idor import IDORValidator, idor_validator
from app.validation.validators.jwt import JWTValidator, jwt_validator
from app.validation.validators.open_redirect import OpenRedirectValidator, open_redirect_validator
from app.validation.validators.path_traversal import (
    PathTraversalValidator,
    path_traversal_validator,
)
from app.validation.validators.rce import RCEValidator, rce_validator
from app.validation.validators.slowloris import SlowlorisValidator, slowloris_validator
from app.validation.validators.sqli import SQLiValidator, sqli_validator
from app.validation.validators.ssrf import SSRFValidator, ssrf_validator
from app.validation.validators.xss import XSSValidator, xss_validator

_VALIDATOR_REGISTRY: dict[str, BaseVulnerabilityValidator] = {
    "slowloris": slowloris_validator,
    "sqli": sqli_validator,
    "sql_injection": sqli_validator,
    "xss": xss_validator,
    "cross_site_scripting": xss_validator,
    "rce": rce_validator,
    "remote_code_execution": rce_validator,
    "ssrf": ssrf_validator,
    "server_side_request_forgery": ssrf_validator,
    "path_traversal": path_traversal_validator,
    "lfi": path_traversal_validator,
    "idor": idor_validator,
    "bola": idor_validator,
    "auth_bypass": auth_bypass_validator,
    "file_upload": file_upload_validator,
    "open_redirect": open_redirect_validator,
    "cors": cors_validator,
    "csrf": csrf_validator,
    "jwt": jwt_validator,
    "session": jwt_validator,
    "authorization": authorization_validator,
    "bfla": authorization_validator,
    "authentication": auth_bypass_validator,
    "command_injection": rce_validator,
    "slowloris_dos": slowloris_validator,
}

validator_registry = ValidatorRegistry()
for _validator in set(_VALIDATOR_REGISTRY.values()):
    _aliases = [
        name
        for name, value in _VALIDATOR_REGISTRY.items()
        if value is _validator and name != _validator.vulnerability_type
    ]
    validator_registry.register(_validator, *_aliases)


def get_validator(vulnerability_type: str) -> BaseVulnerabilityValidator | None:
    """Retrieve specific validator instance for a given vulnerability type."""
    return validator_registry.get(vulnerability_type)


__all__ = [
    "AuthBypassValidator",
    "AuthorizationValidator",
    "BaseVulnerabilityValidator",
    "CORSValidator",
    "CSRFValidator",
    "FileUploadValidator",
    "IDORValidator",
    "JWTValidator",
    "OpenRedirectValidator",
    "PathTraversalValidator",
    "RCEValidator",
    "SQLiValidator",
    "SSRFValidator",
    "SlowlorisValidator",
    "ValidatorRegistry",
    "XSSValidator",
    "auth_bypass_validator",
    "authorization_validator",
    "cors_validator",
    "csrf_validator",
    "file_upload_validator",
    "get_validator",
    "idor_validator",
    "jwt_validator",
    "open_redirect_validator",
    "path_traversal_validator",
    "rce_validator",
    "slowloris_validator",
    "sqli_validator",
    "ssrf_validator",
    "validator_registry",
    "xss_validator",
]
