"""Specialized Vulnerability Validators Package."""

from typing import Dict, Optional

from app.validation.validators.base import BaseVulnerabilityValidator
from app.validation.validators.slowloris import SlowlorisValidator, slowloris_validator
from app.validation.validators.sqli import SQLiValidator, sqli_validator
from app.validation.validators.xss import XSSValidator, xss_validator
from app.validation.validators.rce import RCEValidator, rce_validator
from app.validation.validators.ssrf import SSRFValidator, ssrf_validator
from app.validation.validators.path_traversal import PathTraversalValidator, path_traversal_validator
from app.validation.validators.idor import IDORValidator, idor_validator
from app.validation.validators.auth_bypass import AuthBypassValidator, auth_bypass_validator
from app.validation.validators.file_upload import FileUploadValidator, file_upload_validator
from app.validation.validators.open_redirect import OpenRedirectValidator, open_redirect_validator
from app.validation.validators.cors import CORSValidator, cors_validator

_VALIDATOR_REGISTRY: Dict[str, BaseVulnerabilityValidator] = {
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
}


def get_validator(vulnerability_type: str) -> Optional[BaseVulnerabilityValidator]:
    """Retrieve specific validator instance for a given vulnerability type."""
    clean_type = vulnerability_type.lower().strip()
    return _VALIDATOR_REGISTRY.get(clean_type)


__all__ = [
    "BaseVulnerabilityValidator",
    "SlowlorisValidator",
    "slowloris_validator",
    "SQLiValidator",
    "sqli_validator",
    "XSSValidator",
    "xss_validator",
    "RCEValidator",
    "rce_validator",
    "SSRFValidator",
    "ssrf_validator",
    "PathTraversalValidator",
    "path_traversal_validator",
    "IDORValidator",
    "idor_validator",
    "AuthBypassValidator",
    "auth_bypass_validator",
    "FileUploadValidator",
    "file_upload_validator",
    "OpenRedirectValidator",
    "open_redirect_validator",
    "CORSValidator",
    "cors_validator",
    "get_validator",
]
