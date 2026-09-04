"""Test the real AI preflight/review/report path using synthetic .invalid data.

No target HTTP requests, tools, findings mutations, or Hermes calls are made.
Only synthetic text is sent to the already-configured LLM endpoint. A successful
run proves this sample's contract, not scan recall, pricing, or unlimited quota.
"""
from __future__ import annotations

import argparse
import asyncio
import copy
import json
import time
from pathlib import Path
from types import SimpleNamespace

from app.ai import scan_loop
from app.intelligence.llm_client import LLMClient
from app.reporting.engine import ReportEngine


async def verify(model: str | None, routing_mode: str | None, output: Path) -> dict:
    client = LLMClient(model=model, routing_mode=routing_mode)
    client.hermes_base_url = ""
    if not client.is_configured:
        raise RuntimeError("The configured LLM endpoint is unavailable or disabled")
    scan_loop.llm_client = client
    target = "https://app.example.invalid/account"
    engagement = {
        "platform": "Private", "authorization_reference": "SYNTHETIC-NO-NETWORK",
        "scope_hosts": ["app.example.invalid"], "excluded_hosts": ["excluded.example.invalid"],
        "allowed_ports": [443], "max_rps": 1,
        "allowed_techniques": ["safe_probe", "validation"],
        "prohibited_techniques": ["No denial of service", "No credential attacks", "No data extraction"],
        "notes": "Fictional fixture: analyze the supplied text only. Do not contact any target or run tools.",
    }
    snapshot = {
        "findings": [{"id": "synthetic-candidate", "title": "Synthetic authorization candidate",
            "severity": "INFO", "evidence_level": "CANDIDATE", "validation_status": "CANDIDATE",
            "description": "One fictional HTTP 200 observation without an owner/control comparison. No vulnerability is confirmed."}],
        "coverage_failures": ["Synthetic validator unavailable; authorization comparison was not executed."],
        "endpoints": [target],
    }
    original = copy.deepcopy(snapshot)
    ctx = SimpleNamespace(action_allowed=lambda name: name in {"nuclei", "idor", "idor_validator"})
    started = time.monotonic()
    pre = await scan_loop.scan_ai_controller.preflight(target=target, profile="deep_bug_hunt",
        scope_mode="focused", validation_level="L2_SAFE_ACTIVE", engagement=engagement, ctx=ctx)
    pre_seconds = round(time.monotonic() - started, 3)
    print(json.dumps({"stage": "preflight", "status": pre["status"], "mode": pre["mode"],
                      "seconds": pre_seconds, "routing": pre.get("routing", {})}), flush=True)
    started = time.monotonic()
    post = await scan_loop.scan_ai_controller.post_tools(target=target, profile="deep_bug_hunt",
        engagement=engagement, snapshot=snapshot, ctx=ctx)
    post_seconds = round(time.monotonic() - started, 3)
    print(json.dumps({"stage": "post_tools", "status": post["status"], "mode": post["mode"],
                      "seconds": post_seconds, "routing": post.get("routing", {})}), flush=True)
    report = ReportEngine.generate_markdown("synthetic-ai-contract", target,
        {"report_context": {"ai_analysis": {"preflight": pre, "post_tools": post}}}, [], [], [], [], snapshot["findings"])
    checks = {
        "preflight_cloud_analysis": pre["mode"] == "cloud_ai_with_deterministic_guard",
        "post_tools_cloud_analysis": post["mode"] == "cloud_ai_with_deterministic_guard",
        "baseline_preserved": pre["baseline_stages"] == scan_loop.BASELINE_STAGES,
        "prohibitions_preserved": set(engagement["prohibited_techniques"]).issubset(pre["cautions"]),
        "coverage_failures_preserved": set(snapshot["coverage_failures"]).issubset(post["coverage_gaps"]),
        "evidence_not_mutated": snapshot == original,
        "report_contains_ai_review": "AI Evidence Review & Recommended Next Actions" in report,
        "report_contains_coverage_gap": snapshot["coverage_failures"][0] in report,
        "hermes_not_used": all(not str(attempt).startswith("hermes:") for stage in (pre, post)
                              for attempt in stage.get("routing", {}).get("attempts", [])),
    }
    result = {"ok": all(checks.values()), "synthetic_only": True, "target_requests": 0,
              "model": client.model, "routing_mode": client.effective_routing_mode,
              "latency_seconds": {"preflight": pre_seconds, "post_tools": post_seconds},
              "checks": checks, "preflight": pre, "post_tools": post}
    output.mkdir(parents=True, exist_ok=True)
    (output / "ai-pipeline.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    (output / "synthetic-ai-report.md").write_text("# SYNTHETIC AI CONTRACT TEST — NOT A REAL VULNERABILITY REPORT\n\n" + report, encoding="utf-8")
    print(json.dumps({"ok": result["ok"], "checks": checks, "output": str(output)}, indent=2), flush=True)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model")
    parser.add_argument("--routing-mode", choices=["single", "router_combo", "task_router"])
    parser.add_argument("--output", type=Path, default=Path("scratch/verification/ai-pipeline"))
    args = parser.parse_args()
    result = asyncio.run(verify(args.model, args.routing_mode, args.output))
    raise SystemExit(0 if result["ok"] else 1)
