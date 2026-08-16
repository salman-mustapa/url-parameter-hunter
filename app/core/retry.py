from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable, TypeVar

logger = logging.getLogger("retry")

T = TypeVar("T")

NO_RETRY = ("scope violation", "invalid target", "404", "Out of scope")


async def with_retry(fn: Callable[..., Awaitable[T]], *args: Any, attempts: int = 3, base_delay: float = 1.0, **kwargs: Any) -> T:
    last_exc: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            return await fn(*args, **kwargs)
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            msg = str(exc).lower()
            if any(token in msg for token in NO_RETRY) or attempt == attempts:
                raise
            delay = base_delay * (2 ** (attempt - 1))
            logger.debug("retry %s attempt %d/%d after %.1fs: %s", getattr(fn, "__name__", fn), attempt, attempts, delay, exc)
            await asyncio.sleep(delay)
    raise last_exc  # type: ignore[misc]