"""Compatibility entrypoint for the collected-evidence validator."""

from app.validation.validators.mechanisms import OpenRedirectValidator

open_redirect_validator = OpenRedirectValidator()
