"""Compatibility entrypoint for the collected-evidence validator."""

from app.validation.validators.mechanisms import CSRFValidator

csrf_validator = CSRFValidator()
