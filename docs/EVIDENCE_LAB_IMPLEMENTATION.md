# Evidence validation implementation audit

## Phase 1 — repository audit (2026-08-28)

This is an incremental change to the existing FastAPI application, not a replacement.
The working tree already contained application, UI, reporting and engagement changes;
those changes are retained.

| Area | Existing implementation | Gap found |
| --- | --- | --- |
| Entry/API | `app/main.py`, `app/api/router.py` | Existing authenticated API and scan endpoints |
| Recon/scanning | `app/scanners`, `app/discovery`, tool adapters | Observations must not imply confirmation |
| Attack execution | `app/attacks`, `scan_manager` continuous worker | Worker trusts `is_vulnerable` without mechanism proof |
| Validation | `app/validation/validators`, contracts, quality gate | Registry disconnected from production; caller booleans trusted; baseline/PoC checks claim success without checking |
| Slowloris | `validators/slowloris.py` | Normal GET plus supplied starvation flag; fabricated socket telemetry and irrelevant curl PoC |
| Evidence/findings | typed evidence, lifecycle, SQLAlchemy Finding/Evidence/EvidencePackage | Missing evidence IDs/context; no redaction at typed serialization; unrestricted state transitions |
| Authentication | `core/session_context.py`, `ai/identity_context.py` | Similar 200 responses and roles used as authentication/authorization proof |
| AI/reasoning | `ai/reasoning_layer.py`, hypothesis engine, decision policy | No enforced evidence reference contract; chain descriptions can invent outcomes |
| Workers | `workers/worker_pool.py`, orchestrators, scheduler | Reuse existing pipeline; enforce proof at persistence/dispatch boundaries |
| Scope/rate/config | scope engine, engagement rules, limiter, safety policy | Safety engine not mandatory; no shared probe budget across endpoints |
| Reports/PoC | reporting engine, evidence packages, canonical request recorder | Preserve existing output formats; attach redacted reproducible evidence |
| Local lab | `services/lab_manager.py` | Metadata registry only, no running vulnerable fixture |
| Tests | pytest + frontend Node runtime tests | Existing positive validator tests supply assertions instead of collected proof |

Baseline: `.venv/Scripts/python.exe -m pytest -q`: **188 passed**, 3 warnings.
System Python has no pytest; use the repository virtual environment.
No live public targets are contacted by the new lab tests.

## Implementation sequence

1. Audit (above).
2. Evidence/finding states and redaction.
3. Validator registry and collected-evidence contract.
4. Vulnerability-specific migration and proof gate integration.
5. Bounded loopback incomplete-connection validator.
6. Synthetic authentication and authorization matrix.
7. Data discovery with provenance.
8. Evidence-referenced AI reasoning.
9. Evidence-linked observation graph.
10. Scope/risk/cost-aware next-test selection.
11. Executable local vulnerable application.
12. False-positive regressions.
13. End-to-end lab workflow and complete verification.
