"""Single bounded transport for active validation. Defaults to no authorized destinations.

Only exact loopback origins are supported for active demonstrations. DNS, proxy settings,
automatic redirects, userinfo and arbitrary remote URLs are deliberately not accepted.
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from app.validation.context import ValidationContext


class SafetyViolation(RuntimeError):
    pass


def origin(url: str) -> str:
    try:
        parts = urlsplit(url)
        if (
            parts.scheme not in {"http", "https"}
            or not parts.hostname
            or parts.username
            or parts.password
        ):
            raise ValueError("Invalid HTTP origin")
        host = ipaddress.ip_address(parts.hostname)
        if not host.is_loopback:
            raise ValueError("Active validation requires a loopback IP literal")
        host_text = f"[{host}]" if host.version == 6 else str(host)
        return (
            f"{parts.scheme}://{host_text}:{parts.port or (443 if parts.scheme == 'https' else 80)}"
        )
    except ValueError as exc:
        raise SafetyViolation(str(exc)) from exc


@dataclass(frozen=True)
class AuthorizedScope:
    origins: tuple[str, ...]
    authorization_reference: str

    def __post_init__(self):
        if not self.origins or not self.authorization_reference.strip():
            raise SafetyViolation("Explicit lab origins and authorization reference are required")
        object.__setattr__(self, "origins", tuple(origin(u) for u in self.origins))

    def check(self, url: str) -> None:
        if origin(url) not in self.origins:
            raise SafetyViolation("Destination is outside the configured lab scope")

    def allows(self, url: str) -> bool:
        try:
            self.check(url)
            return True
        except SafetyViolation:
            return False


@dataclass(frozen=True)
class ExecutionLimits:
    requests: int = 80
    concurrency: int = 2
    timeout: float = 2.0
    duration: float = 20.0
    requests_per_second: float = 20.0
    payload_bytes: int = 8192
    response_bytes: int = 131072
    consecutive_errors: int = 3

    def __post_init__(self):
        if any(v <= 0 for v in self.__dict__.values()):
            raise ValueError("All execution limits must be positive")
        if self.concurrency > 5 or self.requests > 500 or self.duration > 60 or self.timeout > 10:
            raise ValueError(
                "Lab hard limits: 5 concurrent, 500 requests, 60s duration, 10s timeout"
            )


class AuthorizedExecutor:
    def __init__(
        self, scope: AuthorizedScope, limits: ExecutionLimits | None = None, *, transport=None
    ):
        self.scope = scope
        self.limits = limits or ExecutionLimits()
        self._client = httpx.AsyncClient(
            transport=transport, trust_env=False, follow_redirects=False
        )
        self._semaphore = asyncio.Semaphore(self.limits.concurrency)
        self._lock = asyncio.Lock()
        self._started = time.monotonic()
        self._last_request = 0.0
        self._count = 0
        self._errors = 0
        self._aborted = False
        self._closed = False

    @property
    def request_count(self):
        return self._count

    def abort(self):
        self._aborted = True

    def _check(self, url: str, size: int):
        self.scope.check(url)
        if self._closed or self._aborted:
            raise SafetyViolation("Executor aborted or closed")
        if self._count >= self.limits.requests:
            raise SafetyViolation("Request limit reached")
        if self._errors >= self.limits.consecutive_errors:
            raise SafetyViolation("Consecutive error abort condition reached")
        if time.monotonic() - self._started >= self.limits.duration:
            raise SafetyViolation("Run duration exceeded")
        if size > self.limits.payload_bytes:
            raise SafetyViolation("Payload size exceeded")

    @asynccontextmanager
    async def slot(self, url: str, size: int = 0):
        self._check(url, size)
        remaining = self.limits.duration - (time.monotonic() - self._started)
        async with asyncio.timeout(min(self.limits.timeout, remaining)):
            async with self._semaphore:
                async with self._lock:
                    self._check(url, size)
                    wait = 1 / self.limits.requests_per_second - (
                        time.monotonic() - self._last_request
                    )
                    if wait > 0:
                        await asyncio.sleep(wait)
                    self._check(url, size)
                    self._count += 1
                    self._last_request = time.monotonic()
                try:
                    yield
                except (httpx.HTTPError, TimeoutError, OSError):
                    self._errors += 1
                    raise

    async def request(
        self,
        run: ValidationContext,
        phase: str,
        method: str,
        url: str,
        *,
        actor: str = "anonymous",
        **kwargs,
    ):
        self.scope.check(run.target)
        if phase in run._exchanges:
            raise ValueError("Evidence phase already recorded")
        if set(kwargs) - {"params", "headers", "content", "json", "data", "cookies"}:
            raise SafetyViolation("Transport overrides are not allowed")
        # Build independent requests: never share cookies between actors or follow redirects.
        req = httpx.Request(method, url, **kwargs)
        if req.headers.get("host", "").lower() != req.url.netloc.decode().lower():
            raise SafetyViolation("Host override is not allowed")
        size = (
            len(str(req.url).encode())
            + len(req.content)
            + sum(len(k) + len(v) for k, v in req.headers.items())
        )
        async with self.slot(str(req.url), size):
            started = time.monotonic()
            response = await self._client.send(req, stream=True, follow_redirects=False)
            try:
                chunks = bytearray()
                async for chunk in response.aiter_bytes():
                    chunks.extend(chunk)
                    if len(chunks) > self.limits.response_bytes:
                        raise SafetyViolation("Response size exceeded")
                captured = httpx.Response(
                    response.status_code,
                    headers=response.headers,
                    content=bytes(chunks),
                    request=req,
                )
            finally:
                await response.aclose()
            self._errors = self._errors + 1 if captured.status_code >= 500 else 0
            run._authorized = True
            return run.record(phase, req, captured, actor, time.monotonic() - started)

    async def aclose(self):
        self._closed = True
        await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.aclose()
