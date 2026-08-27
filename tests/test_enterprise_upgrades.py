"""Tests for Enterprise-grade upgrades: Rate limiting backoff, Redis streams, and subdomain takeover."""

from __future__ import annotations

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from app.core.rate_limit import RateLimiter
from app.orchestration.distributed_queue import DistributedTaskQueue
from app.scanners.dns import check_subdomain_takeover


class TestEnterpriseUpgrades(unittest.TestCase):
    def test_rate_limiter_backoff_and_decay(self) -> None:
        """Verifies that RateLimiter properly backs off and decays towards baseline."""
        limiter = RateLimiter(rps=10.0)
        self.assertEqual(limiter.baseline_delay, 0.1)
        self.assertEqual(limiter.delay, 0.1)
        
        # Test backoff increases delay
        limiter.backoff()
        self.assertAlmostEqual(limiter.delay, 0.18)  # 0.1 * 1.8
        
        limiter.backoff()
        self.assertAlmostEqual(limiter.delay, 0.324)  # 0.18 * 1.8
        
        # Test decay decreases delay towards baseline
        limiter.decay()
        # 0.324 - (0.324 - 0.1) * 0.15 = 0.324 - 0.0336 = 0.2904
        self.assertLess(limiter.delay, 0.324)
        self.assertGreater(limiter.delay, 0.1)
        
        # Decay multiple times to reach baseline
        for _ in range(50):
            limiter.decay()
        self.assertAlmostEqual(limiter.delay, 0.1, places=3)

    def test_distributed_queue_fallback(self) -> None:
        """Verifies that DistributedTaskQueue functions in local fallback mode."""
        async def _test():
            q = DistributedTaskQueue(redis_url="")
            self.assertFalse(q.use_redis)
            
            # Enqueue task
            payload = {"target": "test.com", "scan_id": "123"}
            msg_id = await q.enqueue("scan.validation", payload, "key_abc", priority=90)
            self.assertIsNotNone(msg_id)
            
            # Enqueue duplicate (should deduplicate)
            dup_id = await q.enqueue("scan.validation", payload, "key_abc", priority=90)
            self.assertIsNone(dup_id)
            
            # Claim task
            tasks = await q.claim_tasks("scan.validation", "group_test", "consumer_test", count=1)
            self.assertEqual(len(tasks), 1)
            self.assertEqual(tasks[0]["payload"]["target"], "test.com")
            self.assertEqual(tasks[0]["priority"], 90)
            
            # Claim stale tasks (should reclaim after min_idle_ms)
            await asyncio.sleep(0.1)
            stale = await q.claim_stale_tasks("scan.validation", "group_test", "consumer_new", min_idle_ms=50)
            self.assertEqual(len(stale), 1)
            self.assertEqual(stale[0]["message_id"], msg_id)
            
            # Ack task
            acked = await q.ack("scan.validation", "group_test", msg_id)
            self.assertTrue(acked)
            
            # Queue depth should be 0
            depths = await q.get_queue_depths()
            self.assertEqual(depths.get("scan.validation"), 0)
            
        asyncio.run(_test())

    def test_subdomain_takeover_signature_match(self) -> None:
        """Verifies that check_subdomain_takeover correctly flags matching signatures."""
        async def _test():
            # Mock HTTP response with GitHub pages 404 message
            mock_resp = MagicMock()
            mock_resp.text = "There isn't a GitHub Pages site here"
            
            # We mock httpx.AsyncClient.get to return this response
            with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
                mock_get.return_value = mock_resp
                
                res = await check_subdomain_takeover("test.github.io", "test.github.io")
                self.assertIsNotNone(res)
                self.assertEqual(res["service"], "GitHub Pages")
                self.assertEqual(res["evidence"], "There isn't a GitHub Pages site here")
                
        asyncio.run(_test())


if __name__ == "__main__":
    unittest.main()
