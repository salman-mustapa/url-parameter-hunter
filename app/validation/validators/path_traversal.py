"""Compatibility entrypoint for the collected-evidence validator."""

from app.validation.validators.mechanisms import PathTraversalValidator

path_traversal_validator = PathTraversalValidator()
