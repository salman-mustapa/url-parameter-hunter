"""Compatibility entrypoint for the collected-evidence validator."""

from app.validation.validators.mechanisms import RCEValidator

rce_validator = RCEValidator()
