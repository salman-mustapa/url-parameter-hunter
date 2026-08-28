"""Compatibility entrypoint for the collected-evidence validator."""

from app.validation.validators.mechanisms import SSRFValidator

ssrf_validator = SSRFValidator()
