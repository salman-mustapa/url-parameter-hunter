"""Slowloris telemetry is only collected on the configured loopback lab."""

from app.validation.safety.executor import AuthorizedExecutor
from app.validation.safety.slow_connection import ConnectionSample, collect_incomplete_headers
from app.validation.validators.collected import Decision, EvidenceValidator, repeated


class SlowlorisValidator(EvidenceValidator):
    severity = "LOW"

    def __init__(self):
        super().__init__("slowloris")

    async def probe_local(self, target_url, executor):
        if not isinstance(executor, AuthorizedExecutor):
            raise TypeError("A bounded authorized executor is required")
        run = await collect_incomplete_headers(target_url, executor)
        return await self.validate(target_url, run)

    def assess(self, context):
        baseline, control, test, repeat = repeated(context)
        samples = context.metadata.get("connection_samples", ())
        checks = (
            "No generic HTTP confirmation",
            "No latency-only confirmation",
            "One incomplete socket",
            "150ms observation bound",
            "Repeated complete-request controls",
        )
        if len(samples) != 2 or not all(isinstance(s, ConnectionSample) for s in samples):
            return Decision("INCONCLUSIVE", "Measured local connection telemetry required", checks)
        if not all(e.status == 200 for e in (baseline, control, test, repeat)):
            return Decision("INCONCLUSIVE", "Complete-request controls are not healthy", checks)
        if all(not sample.held for sample in samples):
            return Decision(
                "NOT_VULNERABLE", "Server closed/rejected both bounded incomplete requests", checks
            )
        if all(sample.held for sample in samples):
            return Decision(
                "VALIDATED",
                "Incomplete sockets remained open during two 150ms windows; this does not demonstrate Slowloris DoS or resource exhaustion",
                checks,
            )
        return Decision("INCONCLUSIVE", "Inconsistent incomplete-connection behavior", checks)


slowloris_validator = SlowlorisValidator()
