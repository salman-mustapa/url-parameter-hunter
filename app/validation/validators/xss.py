"""Compatibility entrypoint for the collected-evidence validator."""

from app.validation.validators.mechanisms import XSSValidator

xss_validator = XSSValidator()
