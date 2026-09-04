"""Explicit, small AI endpoint benchmark using synthetic text only (no target scan).

Example: python -m scripts.benchmark_ai --models free security --samples 2
Successful replies do not prove free pricing, unlimited quota, or pentest quality.
"""
import argparse
import asyncio
import json
import time

from app.intelligence.llm_client import LLMClient


async def benchmark(models, samples, timeout, max_tokens=256):
    client = LLMClient()
    client.hermes_base_url = ""  # Measure the requested provider, not a fallback agent.
    if not client.is_configured:
        raise RuntimeError("Configure LLM_ENABLED, LLM_BASE_URL and the appropriate credentials first")
    limit = asyncio.Semaphore(2)

    async def probe(model, sample):
        async with limit:
            started = time.monotonic()
            trace = {}
            try:
                reply = await client.chat(
                    [{"role": "user", "content": 'Return exactly {"status":"ready"} as JSON. No other text.'}],
                    system_prompt="This is a synthetic connectivity and JSON-format test.",
                    model=model, max_tokens=max_tokens, timeout=timeout, _trace=trace,
                )
                parsed = json.loads(reply.strip().removeprefix("```json").removesuffix("```").strip())
                result = {"ok": parsed == {"status": "ready"}}
            except Exception as error:
                result = {"ok": False, "error": type(error).__name__, "error_code": getattr(error, "code", type(error).__name__)}
            return {"model": model, "sample": sample, "seconds": round(time.monotonic() - started, 3),
                    "routing": trace, **result}

    return await asyncio.gather(*(probe(model, i + 1) for model in models for i in range(samples)))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--models", nargs="+", default=["free"])
    parser.add_argument("--samples", type=int, choices=range(1, 4), default=2)
    parser.add_argument("--timeout", type=float, default=12)
    parser.add_argument("--max-tokens", type=int, default=256)
    args = parser.parse_args()
    if not 1 <= args.timeout <= 30 or len(args.models) > 4:
        parser.error("Use timeout 1–30 seconds and at most four models")
    if not 32 <= args.max_tokens <= 2048:
        parser.error("Use a token limit between 32 and 2048")
    print(json.dumps(asyncio.run(benchmark(args.models, args.samples, args.timeout, args.max_tokens)), indent=2))
