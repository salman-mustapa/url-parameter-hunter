import asyncio
import time


class RateLimiter:
    def __init__(self, rps: int):
        self.delay = 1 / max(1, rps)
        self._lock = asyncio.Lock()
        self._last = 0.0

    async def wait(self) -> None:
        async with self._lock:
            now = time.monotonic()
            sleep_for = self.delay - (now - self._last)
            if sleep_for > 0:
                await asyncio.sleep(sleep_for)
            self._last = time.monotonic()
