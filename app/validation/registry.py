"""Validator registry with alias normalization and a fail-closed unknown-type policy."""

from app.validation.validators.base import VulnerabilityValidator


class ValidatorRegistry:
    def __init__(self):
        self._validators = {}

    @staticmethod
    def normalize(name):
        return name.strip().lower().replace("-", "_").replace(" ", "_")

    def register(self, validator: VulnerabilityValidator, *aliases: str):
        contract = validator.contract
        if not contract or contract.allows_status_code_only_confirmation:
            raise ValueError("A safe vulnerability-specific contract is required")
        if not all(
            (
                contract.detection_strategy,
                contract.validation_strategy,
                contract.required_evidence,
                contract.rejection_rules,
            )
        ):
            raise ValueError(
                "Detection, validation, evidence and false-positive checks are mandatory"
            )
        names = [self.normalize(n) for n in (validator.vulnerability_type, *aliases)]
        if any(n in self._validators for n in names):
            raise ValueError("Validator name or alias already registered")
        for name in names:
            self._validators[name] = validator

    def get(self, name):
        return self._validators.get(self.normalize(name))

    def all(self):
        return list({id(v): v for v in self._validators.values()}.values())
