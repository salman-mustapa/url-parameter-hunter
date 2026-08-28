"""Bounded incomplete-header experiment: one socket at a time, no resource exhaustion."""

import asyncio
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.validation.context import ValidationContext
from app.validation.evidence.typed_evidence import Evidence, EvidenceType
from app.validation.safety.executor import AuthorizedExecutor, SafetyViolation


@dataclass(frozen=True)
class ConnectionSample:
    elapsed: float
    held: bool
    observation_window: float


async def collect_incomplete_headers(
    target: str, executor: AuthorizedExecutor
) -> ValidationContext:
    executor.scope.check(target)
    parsed = urlsplit(target)
    if parsed.scheme != "http":
        raise SafetyViolation("Synthetic incomplete-header test supports loopback HTTP only")
    run = ValidationContext(target, "slowloris")
    samples = []
    for phase in ("baseline", "control"):
        await executor.request(run, phase, "GET", target)
    for index in range(2):
        partial = f"GET / HTTP/1.1\r\nHost: {parsed.netloc}\r\nX-Lab-Partial: ".encode()
        async with executor.slot(target, len(partial)):
            reader, writer = await asyncio.open_connection(parsed.hostname, parsed.port or 80)
            start = time.monotonic()
            try:
                writer.write(partial)
                await writer.drain()
                try:
                    # A response or EOF means the server did not retain the incomplete request.
                    await asyncio.wait_for(reader.read(1), timeout=0.15)
                    held = False
                except TimeoutError:
                    held = True
                samples.append(ConnectionSample(time.monotonic() - start, held, 0.15))
            finally:
                writer.close()
                await writer.wait_closed()
        await executor.request(run, "test" if index == 0 else "repeat", "GET", target)
    run.metadata["connection_samples"] = tuple(samples)
    for sample in samples:
        run.add_observation(
            Evidence(
                EvidenceType.NETWORK_BEHAVIOR,
                "Incomplete HTTP header observation",
                "One incomplete loopback socket; closed by collector after at most 150ms",
                data={
                    "held": sample.held,
                    "elapsed": sample.elapsed,
                    "observation_window": sample.observation_window,
                    "max_incomplete_sockets": 1,
                },
                asset=target,
                confidence=1,
                relevance=1,
            )
        )
    return run
