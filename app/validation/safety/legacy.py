"""Fail-closed compatibility transport for pre-registry HTTP adapters.

Legacy adapters may collect observations only inside an explicitly installed bounded
executor. They cannot create their own HTTP clients or perform unbounded socket probes.
"""

from contextlib import contextmanager
from contextvars import ContextVar
from uuid import uuid4

import httpx

from app.validation.context import ValidationContext
from app.validation.safety.executor import AuthorizedExecutor, SafetyViolation

_executor: ContextVar[AuthorizedExecutor | None] = ContextVar("authorized_validation_executor", default=None)


@contextmanager
def use_executor(executor):
    if not isinstance(executor, AuthorizedExecutor):
        raise SafetyViolation("A bounded executor is mandatory")
    token = _executor.set(executor)
    try:
        yield
    finally:
        _executor.reset(token)


class ValidationHTTPClient:
    def __init__(self, **kwargs):
        self.executor = _executor.get()
        if self.executor is None:
            raise SafetyViolation("Legacy active validation requires an authorized bounded executor")
        if kwargs.get("proxy") or kwargs.get("proxies"):
            raise SafetyViolation("Validation proxies are not supported")
        self.headers = dict(kwargs.get("headers") or {})
        self.cookies = dict(kwargs.get("cookies") or {})

    async def request(self, method, url, **kwargs):
        kwargs.pop("timeout", None)
        kwargs.pop("follow_redirects", None)
        headers = dict(self.headers)
        headers.update(kwargs.pop("headers", {}) or {})
        cookies = dict(self.cookies)
        cookies.update(kwargs.pop("cookies", {}) or {})
        run = ValidationContext(str(url), "legacy_observation")
        exchange = await self.executor.request(run, uuid4().hex, method, str(url),
                                                headers=headers, cookies=cookies, **kwargs)
        return httpx.Response(exchange.status, headers=dict(exchange.headers), content=exchange.body.encode(),
                              request=httpx.Request(exchange.method, exchange.url))

    async def get(self, url, **kwargs):
        return await self.request("GET", url, **kwargs)

    async def post(self, url, **kwargs):
        return await self.request("POST", url, **kwargs)

    async def put(self, url, **kwargs):
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url, **kwargs):
        return await self.request("DELETE", url, **kwargs)

    async def aclose(self):
        pass  # The executor owner closes the shared transport.

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


async def unsupported_socket_probe(*args, **kwargs):
    raise SafetyViolation("Legacy raw-socket active probing is disabled; use a bounded protocol validator")
