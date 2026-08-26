import asyncio
import time


class RateLimiter:
    def __init__(self, rps: int):
        self.baseline_delay = 1 / max(1, rps)
        self.delay = self.baseline_delay
        self.max_delay = 10.0
        self._lock = asyncio.Lock()
        self._last = 0.0

    async def wait(self) -> None:
        async with self._lock:
            now = time.monotonic()
            sleep_for = self.delay - (now - self._last)
            if sleep_for > 0:
                await asyncio.sleep(sleep_for)
            self._last = time.monotonic()

    def backoff(self) -> None:
        """Exponential backoff when encountering rate limiting or WAF block."""
        if self.delay <= 0:
            self.delay = 0.1
        else:
            self.delay = min(self.max_delay, self.delay * 1.8)

    def decay(self) -> None:
        """Slowly decay delay back to baseline after successful requests."""
        if self.delay > self.baseline_delay:
            # Shift 15% closer to baseline delay
            self.delay = max(self.baseline_delay, self.delay - (self.delay - self.baseline_delay) * 0.15)

