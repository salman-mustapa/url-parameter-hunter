"""Compatibility entrypoint for the collected-evidence validator."""

from app.validation.validators.mechanisms import CORSValidator

cors_validator = CORSValidator()
