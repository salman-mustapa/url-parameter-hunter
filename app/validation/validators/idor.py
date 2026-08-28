"""Compatibility entrypoint for the collected-evidence validator."""

from app.validation.validators.mechanisms import IDORValidator

idor_validator = IDORValidator()
