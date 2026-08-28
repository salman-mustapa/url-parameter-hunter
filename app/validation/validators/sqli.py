"""Compatibility entrypoint for the collected-evidence validator."""

from app.validation.validators.mechanisms import SQLiValidator

sqli_validator = SQLiValidator()
