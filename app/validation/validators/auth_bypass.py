"""Compatibility entrypoint for the collected-evidence validator."""

from app.validation.validators.mechanisms import AuthBypassValidator

auth_bypass_validator = AuthBypassValidator()
