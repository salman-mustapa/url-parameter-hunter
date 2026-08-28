"""Smoke-test a disposable QA server; never accepts a non-loopback destination.

Start with python -m scripts.serve_local_qa, then python -m scripts.verify_local.
Generated reports contain synthetic data and are saved beneath scratch/verification.
"""

import argparse
import asyncio
import hashlib
import ipaddress
import json
import re
import statistics
import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx


async def verify(base, output):
    parts = urlsplit(base)
    if parts.scheme != "http" or not ipaddress.ip_address(parts.hostname).is_loopback:
        raise ValueError("Only a loopback QA server is allowed")
    output.mkdir(parents=True, exist_ok=True)
    async with httpx.AsyncClient(base_url=base, trust_env=False, timeout=40) as client:
        for path in ("/", "/health", "/ready", "/openapi.json", "/js/app.js", "/css/styles.css"):
            assert (await client.get(path)).status_code == 200, path
        schema = (await client.get("/openapi.json")).json()
        checked = []
        public = {"/api/health", "/api/auth/login", "/api/auth/register", "/api/auth/logout", "/api/auth/me", "/api/oob/{correlation_id}"}
        for path, operations in schema["paths"].items():
            if not path.startswith("/api/") or path in public:
                continue
            for method in operations:
                if method.upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                    continue
                url = re.sub(r"\{[^}]+\}", "missing-id", path)
                response = await client.request(method, url, json={} if method != "get" else None)
                assert response.status_code == 401, (method, path, response.status_code)
                checked.append(f"{method.upper()} {path}")
        login = await client.post("/api/auth/login", json={"username": "qa_operator", "password": "Local-QA-Only-2026!"})
        assert login.status_code == 200, "Synthetic QA login failed"
        client.headers["Authorization"] = "Bearer " + login.json()["access_token"]
        run = await client.post("/api/labs/synthetic/run")
        assert run.status_code == 200, run.text
        result = run.json()
        scan_id, finding_id = result["scan_id"], result["finding_ids"][0]
        assert result["status"] == "CONFIRMED"
        assert (await client.get(f"/api/scans/{scan_id}")).json()["status"] == "completed"
        for suffix in ("workspace", "events/history", "findings", "assets/all", "urls/all"):
            response = await client.get(f"/api/scans/{scan_id}/{suffix}")
            assert response.status_code == 200, (suffix, response.status_code)
        evidence = await client.get(f"/api/findings/{finding_id}/evidence-package")
        assert evidence.status_code == 200
        report_hashes = {}
        for extension, endpoint in (("md", "markdown"), ("html", "html"), ("pdf", "pdf"), ("json", "json")):
            response = await client.get(f"/api/scans/{scan_id}/report/{endpoint}")
            assert response.status_code == 200, (endpoint, response.text[:200])
            if extension == "pdf":
                assert response.content.startswith(b"%PDF-")
            (output / f"synthetic-report.{extension}").write_bytes(response.content)
            report_hashes[extension] = hashlib.sha256(response.content).hexdigest()
        job = await client.post(f"/api/scans/{scan_id}/export/investigation_json")
        assert job.status_code in {200, 202}, job.text
        async with asyncio.timeout(20):
            while True:
                jobs = (await client.get(f"/api/scans/{scan_id}/exports")).json()
                if jobs and jobs[0]["status"] in {"COMPLETED", "FAILED"}:
                    break
                await asyncio.sleep(0.1)
        assert jobs[0]["status"] == "COMPLETED", jobs[0]
        download = await client.get(jobs[0]["download_url"])
        assert hashlib.sha256(download.content).hexdigest() == jobs[0]["sha256_hash"]
        async with client.stream("GET", f"/api/scans/{scan_id}/events") as stream:
            assert stream.status_code == 200
            async for line in stream.aiter_lines():
                if line.startswith("data:"):
                    assert json.loads(line[5:])
                    break

        limiter = asyncio.Semaphore(5)
        async def measure():
            async with limiter:
                started = time.perf_counter()
                response = await client.get("/ready")
                assert response.status_code == 200
                return (time.perf_counter() - started) * 1000
        samples = sorted(await asyncio.gather(*(measure() for _ in range(50))))
        summary = {"scan_id": scan_id, "finding_id": finding_id, "status": result["status"],
                   "protected_api_operations_checked": len(checked), "request_count": result["request_count"],
                   "report_sha256": report_hashes, "async_export": "COMPLETED", "sse": "received",
                   "readiness_requests": 50, "concurrency": 5,
                   "latency_ms": {"median": round(statistics.median(samples), 2),
                                  "p95": round(samples[47], 2), "max": round(max(samples), 2)}}
        (output / "api-operations.json").write_text(json.dumps(checked, indent=2), encoding="utf-8")
        (output / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="http://127.0.0.1:19001")
    parser.add_argument("--output", type=Path, default=Path("scratch/verification"))
    args = parser.parse_args()
    asyncio.run(verify(args.base, args.output))
