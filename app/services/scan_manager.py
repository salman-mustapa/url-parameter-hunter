from __future__ import annotations

import asyncio
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import func, select

from app.attacks import get_attack_module
from app.core.config import settings
from app.core.db import AsyncSessionLocal, async_session_scope
from app.core.events import event_bus
from app.core.kill_switch import kill_switch_manager
from app.core.rate_limit import RateLimiter
from app.core.scope_engine import ScopeEngine, normalize_target
from app.core.session_context import SessionContext, SessionIdentity
from app.discovery.parameter_classifier import parameter_classifier
from app.intelligence.attack_graph import attack_graph_engine
from app.models.models import Asset, Certificate, Domain, Finding, Parameter, Port, Scan, Screenshot, Technology, URL
from app.orchestration.attack_opportunity import AttackOpportunity, OpportunityState, opportunity_bus
from app.scanners import dns, http, port, screenshot, security, subdomain, web
from app.scanners.base import ScanContext
from app.services.capability_registry import AssessmentProfile, ValidationLevel
from app.services.results import result_service

logger = logging.getLogger("scan_mgr")


class ScanManager:
    def __init__(self) -> None:
        self._running: Dict[str, asyncio.Task] = {}
        self._pause_events: Dict[str, asyncio.Event] = {}
        self._stop_flags: Dict[str, bool] = {}

    # ---------- public control ----------
    async def create_scan(
        self,
        target: str,
        profile: str = "autonomous",
        include_subdomains: bool = True,
        validation_level: Optional[str] = None,
        user_id: Optional[str] = None,
        allowed_modules: Optional[list] = None,
        allowed_actions: Optional[list] = None,
        authorization_id: Optional[str] = None,
        authorization_reference: Optional[str] = None,
        campaign_id: Optional[str] = None,
    ) -> dict:
        host, root_domain = normalize_target(target)
        prof = "autonomous"
        val_level = ValidationLevel.L4_HIGH_RISK

        # Defensive handling if callers swapped include_subdomains and validation_level
        if isinstance(include_subdomains, str):
            include_subdomains = True
        elif isinstance(validation_level, bool):
            include_subdomains = validation_level

        # Full Autonomous Security Engine Options (Highest Capability by default)
        options: Dict[str, Any] = {
            "port_scan": True,
            "web_discovery": True,
            "parameter_discovery": True,
            "security_checks": True,
            "deep_crawl": True,
            "deep_parameter_fuzzing": True,
            "js_analysis": True,
            "nmap_vuln": True,
            "cve_matching": True,
            "nonstandard_ports": True,
            "auth_testing": True,
            "artifact_extraction": True,
            "include_subdomains": include_subdomains,
            "target_host": host,
            "target_url": target if "://" in target else f"http://{target}",
            "max_assets": settings.max_assets_per_scan,
            "max_urls": settings.max_urls_per_scan,
            "max_runtime_seconds": settings.max_runtime_minutes * 60,
            "validation_level": val_level,
            "authorization_reference": authorization_reference or "AUTONOMOUS_OPERATOR",
            "authorized_high_risk": True,
            "performance_mode": settings.performance_mode,
            "strict_scope": True,
        }

        scan_id = f"inv_{int(time.time())}_{uuid.uuid4().hex[:6]}_{host.replace('.', '_')}"
        camp_id = campaign_id or f"camp_{int(time.time())}_{uuid.uuid4().hex[:6]}"

        async with AsyncSessionLocal() as db:
            # Ensure Domain entity exists (§5, §36)
            domain_entity = (await db.execute(select(Domain).where(Domain.name == root_domain))).scalar_one_or_none()
            if not domain_entity:
                domain_entity = Domain(name=root_domain, health_status="ACTIVE", risk_level="LOW")
                db.add(domain_entity)
                await db.flush()

            scan = Scan(
                id=scan_id,
                campaign_id=camp_id,
                user_id=user_id,
                domain_id=domain_entity.id,
                root_domain=root_domain,
                status="queued",
                profile="autonomous",
                validation_level=val_level,
                options=options,
                authorization_id=authorization_id,
                authorization_reference=authorization_reference or "AUTONOMOUS_OPERATOR",
                allowed_modules=allowed_modules or [],
                allowed_actions=allowed_actions or [],
                heartbeat_at=datetime.now(timezone.utc),
            )
            db.add(scan)
            await db.commit()

        await event_bus.publish(result_service.make_event(
            scan_id, "investigation.started", f"Autonomous security investigation initiated for {root_domain}",
            target=root_domain, profile="autonomous", validation_level=val_level, severity="info"))
        self._run(scan_id, root_domain, prof, options)
        return {
            "scan_id": scan_id,
            "investigation_id": scan_id,
            "campaign_id": camp_id,
            "status": "queued",
            "target": root_domain,
            "profile": "autonomous",
            "validation_level": val_level,
        }


    def _run(self, scan_id: str, root_domain: str, profile: str, options: Dict[str, Any]) -> None:
        if scan_id in self._running:
            return
        ev = asyncio.Event()
        ev.set()
        self._pause_events[scan_id] = ev
        self._stop_flags[scan_id] = False
        task = asyncio.create_task(
            self._run_with_timeout(scan_id, root_domain, profile, options)
        )
        self._running[scan_id] = task

        def _cleanup(done_task: asyncio.Task) -> None:
            self._running.pop(scan_id, None)
            try:
                done_task.result()
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                logger.warning("Scan pipeline task ended with error for %s: %s", scan_id, exc)

        task.add_done_callback(_cleanup)

    async def _run_with_timeout(
        self,
        scan_id: str,
        root_domain: str,
        profile: str,
        options: Dict[str, Any],
    ) -> None:
        timeout_seconds = max(30.0, float(options.get("max_runtime_seconds") or settings.max_runtime_minutes * 60))
        try:
            await asyncio.wait_for(
                self._pipeline(scan_id, root_domain, profile, options),
                timeout=timeout_seconds,
            )
        except asyncio.TimeoutError:
            logger.error("Scan %s reached its runtime budget of %.0f seconds. Gracefully finalizing telemetry...", scan_id, timeout_seconds)
            try:
                from app.core.security_engine import security_engine
                security_engine.complete_scan(scan_id)
            except Exception:
                pass
            await self._finish_status(scan_id, "timeout")
            await event_bus.publish(result_service.make_event(
                scan_id,
                "scan.timeout",
                f"Scan reached the {timeout_seconds:.0f}s runtime budget. Discovered assets, endpoints, and findings preserved.",
                severity="warn",
            ))

    async def resume_pending_scans(self, max_scans: Optional[int] = None) -> None:
        """Startup handler to rehydrate and resume running/queued scans."""
        async with async_session_scope() as db:
            stmt = select(Scan).where(Scan.status.in_(["running", "queued"])).order_by(Scan.created_at.desc())
            if max_scans is not None:
                stmt = stmt.limit(max(0, int(max_scans)))
            pending_scans = (await db.execute(stmt)).scalars().all()

            for scan in pending_scans:
                logger.info("Resuming pending/interrupted scan %s for %s", scan.id, scan.root_domain)
                self._run(scan.id, scan.root_domain, scan.profile, scan.options)

    async def pause(self, scan_id: str) -> None:
        ev = self._pause_events.get(scan_id)
        if ev:
            ev.clear()
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan:
                scan.status = "paused"
                await db.commit()
        await event_bus.publish(result_service.make_event(
            scan_id, "scan.paused", "Scan paused", severity="warn"))

    async def resume(self, scan_id: str) -> None:
        ev = self._pause_events.get(scan_id)
        if ev:
            ev.set()
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan:
                scan.status = "running"
                scan.started_at = scan.started_at or datetime.now(timezone.utc)
                await db.commit()
        await event_bus.publish(result_service.make_event(
            scan_id, "scan.resumed", "Scan resumed", severity="info"))

    async def stop(self, scan_id: str) -> None:
        self._stop_flags[scan_id] = True
        kill_switch_manager.stop_campaign(scan_id)
        task = self._running.get(scan_id)
        if task:
            task.cancel()
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan and scan.status not in ("completed", "stopped", "cancelled"):
                scan.status = "stopped"
                scan.completed_at = datetime.now(timezone.utc)
                scan.kill_switch = True
                await db.commit()
        await event_bus.publish(result_service.make_event(
            scan_id, "scan.stopped", "Scan stopped by operator (kill switch activated)", severity="warn"))

    # ---------- pipeline ----------
    async def _pipeline(self, scan_id: str, root_domain: str, profile: str, options: Dict[str, Any]) -> None:
        target_host = options.get("target_host") or root_domain
        include_subdomains = options.get("include_subdomains", True)

        if not include_subdomains:
            scope = ScopeEngine(
                target_host,
                allowed_hosts=[target_host],
                recursive=False,
                allow_private_networks=settings.allow_private_networks,
            )
        else:
            scope = ScopeEngine(
                root_domain,
                recursive=True,
                allow_private_networks=settings.allow_private_networks,
            )

        limiter = RateLimiter(settings.rate_limit_rps)
        ctx = ScanContext(scan_id, scope, profile, options, limiter)

        start_time = time.time()
        phase_failures: list[dict[str, str]] = []
        session_ctx: Optional[SessionContext] = None
        val_stop_event: Optional[asyncio.Event] = None
        val_worker_task: Optional[asyncio.Task] = None
        try:
            # Rehydrate from checkpoint if present
            async with async_session_scope() as db:
                scan_rec = await db.get(Scan, scan_id)
                if scan_rec and scan_rec.checkpoint:
                    cp = scan_rec.checkpoint
                    if "opportunities" in cp:
                        from app.orchestration.attack_opportunity import AttackOpportunity, opportunity_bus
                        # Rehydrate seen fingerprints
                        for fp in cp.get("seen_fingerprints", []):
                            opportunity_bus._seen_fingerprints.add(fp)
                        
                        # Rehydrate opportunities
                        count_rehydrated = 0
                        for opp_dict in cp["opportunities"]:
                            opp = AttackOpportunity.from_dict(opp_dict)
                            if opp.id not in opportunity_bus._opportunities:
                                await opportunity_bus.publish(opp)
                                count_rehydrated += 1
                        if count_rehydrated > 0:
                            await ctx.emit(
                                "scan.rehydrated",
                                f"Rehydrated {count_rehydrated} opportunities from checkpoint.",
                                severity="info"
                            )

            from app.core.security_engine import security_engine
            from app.models.application_model import EntityType

            target_label = options.get("target_url") or options.get("target_host") or root_domain

            try:
                security_engine.initialize_scan(scan_id, target_label)
                security_engine.start_discovery(scan_id)
            except Exception as se_err:
                logger.debug("SecurityEngine init: %s", se_err)

            await self._set_status(scan_id, "running", started_at=True)
            await event_bus.publish(result_service.make_event(
                scan_id, "scan.running", f"Pipeline running for {root_domain}", severity="info"))

            # Initialize stateful session context & continuous validation loop
            session_ctx = SessionContext(base_url=f"http://{root_domain}", rate_limiter=ctx.rate_limiter)
            val_stop_event = asyncio.Event()
            val_worker_task = asyncio.create_task(
                self._run_continuous_validation_worker(ctx, scan_id, root_domain, session_ctx, val_stop_event)
            )

            # ---- Phase A: Discovery (subdomains / focused target) ----
            if not kill_switch_manager.is_stopped(scan_id, "discovery"):
                try:
                    await ctx.emit(
                        "pipeline.stage",
                        f"Stage 1/5 [RECON]: Running subfinder & asset discovery on {root_domain}",
                        stage="RECON",
                        tool="subfinder",
                        progress=15,
                        severity="info",
                    )
                    async with async_session_scope() as db:
                        await self._checkpoint(ctx, db, root_domain, start_time)
                        await subdomain.run(ctx, db, root_domain)
                except Exception as phase_err:
                    logger.warning("Discovery phase warning on %s: %s", scan_id, phase_err)
                    phase_failures.append({"phase": "discovery", "error": str(phase_err)[:300]})

            try:
                security_engine.complete_discovery(scan_id)
            except Exception as se_err:
                logger.debug("SecurityEngine complete_discovery: %s", se_err)

            # ---- Phase B: DNS resolution (all assets) ----
            if not kill_switch_manager.is_stopped(scan_id, "dns"):
                try:
                    await ctx.emit(
                        "pipeline.stage",
                        f"Stage 2/5 [DNS]: Resolving DNS records, IP blocks, and CNAMEs on {root_domain}",
                        stage="RECON",
                        tool="dns_resolver",
                        progress=30,
                        severity="info",
                    )
                    async with async_session_scope() as db:
                        await self._checkpoint(ctx, db, root_domain, start_time)
                        await dns.run(ctx, db, root_domain)
                except Exception as phase_err:
                    logger.warning("DNS phase warning on %s: %s", scan_id, phase_err)
                    phase_failures.append({"phase": "dns", "error": str(phase_err)[:300]})

            # ---- Phase C (parallel): Port scan || HTTP probe + cert + tech ----
            await ctx.emit(
                "pipeline.stage",
                f"Stage 3/5 [NETWORK]: Probing open ports, TLS certs, and web banners on {root_domain}",
                stage="NETWORK",
                tool="nmap / httpx",
                progress=45,
                severity="info",
            )
            async def run_port():
                if options.get("port_scan", True) and not kill_switch_manager.is_stopped(scan_id, "network"):
                    try:
                        async with async_session_scope() as db:
                            await self._checkpoint(ctx, db, root_domain, start_time)
                            await port.run(ctx, db, root_domain)
                    except Exception as phase_err:
                        logger.warning("Port scan phase warning on %s: %s", scan_id, phase_err)
                        phase_failures.append({"phase": "network", "error": str(phase_err)[:300]})

            async def run_http():
                if not kill_switch_manager.is_stopped(scan_id, "web"):
                    try:
                        async with async_session_scope() as db:
                            await self._checkpoint(ctx, db, root_domain, start_time)
                            await http.run(ctx, db, root_domain)
                    except Exception as phase_err:
                        logger.warning("HTTP probe phase warning on %s: %s", scan_id, phase_err)
                        phase_failures.append({"phase": "http", "error": str(phase_err)[:300]})

            await asyncio.gather(run_port(), run_http())

            # Seed service & artifact opportunities immediately upon port discovery
            try:
                async with async_session_scope() as db:
                    ports_db_seed = (await db.execute(select(Port).join(Asset, Port.asset_id == Asset.id).where(Asset.scan_id == scan_id))).scalars().all()
                    for p in ports_db_seed:
                        port_num = getattr(p, "port_number", None) or getattr(p, "port", None)
                        p_serv = getattr(p, "service", "") or ""
                        if port_num in (80, 443, 8080, 8443, 3000, 8000) or "http" in p_serv.lower():
                            scheme = "https" if port_num in (443, 8443) else "http"
                            target_ep = f"{scheme}://{root_domain}:{port_num}" if port_num not in (80, 443) else f"{scheme}://{root_domain}"
                            for art_module in [get_attack_module("artifact"), get_attack_module("auth")]:
                                if art_module:
                                    art_opps = await art_module.discover(target_ep, {"urls": [target_ep]})
                                    await opportunity_bus.publish_batch(art_opps)
                        elif port_num in (6379, 27017, 9200, 21, 11211, 3306):
                            serv_module = get_attack_module("service")
                            if serv_module:
                                s_opps = await serv_module.discover(root_domain, {"ports": [{"port": port_num, "service": p_serv}]})
                                await opportunity_bus.publish_batch(s_opps)
            except Exception as seed_err:
                logger.debug("Port discovery seeding note: %s", seed_err)

            try:
                from app.intelligence.llm_client import llm_client

                security_engine.start_testing(scan_id)
                app_model = security_engine.get_app_model(scan_id)
                reasoning = security_engine.get_reasoning_layer(scan_id)

                if app_model:
                    app_model.add_entity(
                        entity_type=EntityType.ASSET,
                        label=target_label,
                        properties={"ip": options.get("target_host", root_domain)}
                    )

                    # Populate all discovered subdomains, ports, and technologies into app_model
                    async with async_session_scope() as db:
                        assets_db = (await db.execute(select(Asset).where(Asset.scan_id == scan_id).limit(100))).scalars().all()
                        for ast in assets_db:
                            if ast.hostname or ast.ip:
                                app_model.add_entity(
                                    entity_type=EntityType.ASSET,
                                    label=ast.hostname or ast.ip,
                                    properties={"ip": ast.ip, "status": ast.status}
                                )
                        ports_db = (await db.execute(select(Port).join(Asset, Port.asset_id == Asset.id).where(Asset.scan_id == scan_id).limit(50))).scalars().all()
                        urls_db = (await db.execute(select(URL).join(Asset, URL.asset_id == Asset.id).where(Asset.scan_id == scan_id).limit(50))).scalars().all()
                        for u in urls_db:
                            app_model.add_entity(
                                entity_type=EntityType.ENDPOINT,
                                label=u.path or u.url,
                                properties={"url": u.url, "method": u.method or "GET"}
                            )
                        techs_db = (await db.execute(select(Technology).join(Asset, Technology.asset_id == Asset.id).where(Asset.scan_id == scan_id).limit(50))).scalars().all()
                        for t in techs_db:
                            app_model.add_entity(
                                entity_type=EntityType.TECHNOLOGY,
                                label=t.name,
                                properties={"version": t.version, "category": t.category}
                            )

                res = security_engine.run_reasoning_cycle(scan_id)
                if res and res.hypotheses_generated:
                    for hyp in res.hypotheses_generated[:6]:
                        plan = security_engine.create_attack_plan(
                            scan_id=scan_id,
                            title=f"Attack Verification Plan for {hyp.statement[:40]}",
                            target=hyp.target_endpoint or root_domain,
                            tool_sequence=[hyp.next_test or "nuclei", "dalfox"]
                        )
                        if plan:
                            await ctx.emit(
                                "ai.plan_generated",
                                f"🧠 AI Attack Plan: {plan.title} -> [{', '.join(plan.to_dict().get('tool_sequence', []))}]",
                                plan_id=plan.plan_id,
                                target=plan.target,
                                severity="info",
                            )

                # Real-time NineRouter Multi-Model Combo LLM Hypothesis Synthesis
                if llm_client.is_configured and app_model and reasoning:
                    try:
                        assets_list = [{"hostname": a.label, "ip": a.properties.get("ip")} for a in app_model.get_entities_by_type(EntityType.ASSET)]
                        endpoints_list = [{"url": e.properties.get("url"), "path": e.label} for e in app_model.get_entities_by_type(EntityType.ENDPOINT)]
                        techs_list = [{"name": t.label, "version": t.properties.get("version")} for t in app_model.get_entities_by_type(EntityType.TECHNOLOGY)]
                        ports_list = [{"port": p.port_number if hasattr(p, 'port_number') else p.port} for p in ports_db] if 'ports_db' in locals() and ports_db else [{"port": 80}, {"port": 443}]

                        llm_hyps = await llm_client.generate_attack_hypotheses(
                            target_domain=root_domain,
                            assets=assets_list,
                            endpoints=endpoints_list,
                            technologies=techs_list,
                            ports=ports_list,
                        )
                        for lh in llm_hyps:
                            if isinstance(lh, dict) and lh.get("statement"):
                                stmt = lh.get("statement", "")
                                tgt = lh.get("target_endpoint") or root_domain
                                tool_seq = lh.get("tool_sequence") or [lh.get("next_test") or "nuclei", "dalfox"]
                                reasoning.hypothesis_engine.create_hypothesis(
                                    statement=f"[AI Neural] {stmt}",
                                    target_endpoint=tgt,
                                    initial_confidence=float(lh.get("confidence", 0.85)),
                                    exploitability=0.8,
                                    impact=0.8,
                                    chain_potential=0.6,
                                    business_criticality=0.7,
                                    next_test=tool_seq[0] if tool_seq else "nuclei",
                                    expected_result=lh.get("expected_result", "Observable vulnerability evidence"),
                                )
                                plan = security_engine.create_attack_plan(
                                    scan_id=scan_id,
                                    title=lh.get("attack_plan_title") or f"AI Attack Plan for {stmt[:40]}",
                                    target=tgt,
                                    tool_sequence=tool_seq
                                )
                                await ctx.emit(
                                    "ai.hypothesis_formulated",
                                    f"🧠 AI Formulated Hypothesis: [AI Neural] {stmt} (Target: {tgt})",
                                    statement=stmt,
                                    target=tgt,
                                    severity="info",
                                    )
                    except Exception as llm_err:
                        logger.debug("In-flight LLM reasoning note: %s", llm_err)
            except Exception as se_err:
                logger.debug("SecurityEngine start_testing: %s", se_err)

            # ---- Phase D: URL/endpoint discovery + params (web) ----
            if options.get("web_discovery", True) and not kill_switch_manager.is_stopped(scan_id, "crawler"):
                try:
                    await ctx.emit(
                        "pipeline.stage",
                        f"Stage 4/5 [ENUM]: Crawling endpoints, mining parameters, and harvesting routes via Katana/Dirsearch on {root_domain}",
                        stage="ENUM",
                        tool="katana / dirsearch",
                        progress=65,
                        severity="info",
                    )
                    async with async_session_scope() as db:
                        await self._checkpoint(ctx, db, root_domain, start_time)
                        await web.run(ctx, db, root_domain)

                    # Update application model with discovered endpoints and classify parameters
                    app_model = security_engine.get_app_model(scan_id)
                    reasoning = security_engine.get_reasoning_layer(scan_id)
                    async with async_session_scope() as db:
                        urls_res = await db.execute(
                            select(URL).join(Asset, URL.asset_id == Asset.id).where(Asset.scan_id == scan_id).limit(100)
                        )
                        crawled_urls = urls_res.scalars().all()
                        for u in crawled_urls:
                            if app_model:
                                app_model.add_entity(
                                    entity_type=EntityType.ENDPOINT,
                                    label=u.path or u.url or "/",
                                    properties={"url": u.url, "method": u.method or "GET"}
                                )
                            # Immediately feed parameters into Opportunity Bus for concurrent testing
                            if u.url:
                                param_opps = parameter_classifier.generate_hypotheses_for_url(u.url, method=u.method or "GET")
                                await opportunity_bus.publish_batch(param_opps)

                        # Re-run reasoning cycle with new endpoint data
                        if reasoning:
                            res = security_engine.run_reasoning_cycle(scan_id)
                            if res and res.hypotheses_generated:
                                for hyp in res.hypotheses_generated[:5]:
                                    security_engine.create_attack_plan(
                                        scan_id=scan_id,
                                        title=f"Attack Plan for {hyp.statement[:40]}",
                                        target=hyp.target_endpoint or root_domain,
                                        tool_sequence=[hyp.next_test or "nuclei", "dalfox"]
                                    )
                except Exception as phase_err:
                    logger.warning("Web discovery phase warning on %s: %s", scan_id, phase_err)
                    phase_failures.append({"phase": "web_discovery", "error": str(phase_err)[:300]})

            # ---- Phase E: Security intelligence & deep validation ----
            if options.get("security_checks", True) and not kill_switch_manager.is_stopped(scan_id, "validation"):
                try:
                    await ctx.emit(
                        "pipeline.stage",
                        f"Stage 5/5 [EXPLOIT & VERIFY]: Fuzzing injection vectors (SQLi, XSS, SSRF, Auth Bypass) with AI Engine on {root_domain}",
                        stage="EXPLOIT",
                        tool="ai_exploit_engine",
                        progress=85,
                        severity="info",
                    )
                    async with async_session_scope() as db:
                        await self._checkpoint(ctx, db, root_domain, start_time)
                        await security.run(ctx, db, root_domain)
                except Exception as phase_err:
                    logger.warning("Security validation phase warning on %s: %s", scan_id, phase_err)
                    phase_failures.append({"phase": "validation", "error": str(phase_err)[:300]})

            # Drain and stop continuous validation worker
            val_stop_event.set()
            try:
                await asyncio.wait_for(val_worker_task, timeout=15.0)
            except Exception:
                pass
            await session_ctx.close()

            try:
                security_engine.start_validation(scan_id)
            except Exception as se_err:
                logger.debug("SecurityEngine start_validation: %s", se_err)

            # ---- Phase F: Automated Visual Evidence & Screenshot Worker (V4 §10) ----
            if not kill_switch_manager.is_stopped(scan_id, "browser"):
                try:
                    await ctx.emit(
                        "pipeline.stage",
                        f"Packaging cryptographic proofs & visual evidence for {root_domain}",
                        stage="VERIFY",
                        tool="evidence_packager",
                        progress=95,
                        severity="info",
                    )
                    async with async_session_scope() as db:
                        await self._checkpoint(ctx, db, root_domain, start_time)
                        await screenshot.run(ctx, db, root_domain)
                except Exception as phase_err:
                    logger.warning("Screenshot phase warning on %s: %s", scan_id, phase_err)
                    phase_failures.append({"phase": "evidence", "error": str(phase_err)[:300]})

            try:
                security_engine.start_reporting(scan_id)
                security_engine.complete_scan(scan_id)
            except Exception as se_err:
                logger.debug("SecurityEngine complete_scan: %s", se_err)

            # ---- Complete Scan & Update Summary ----
            async with async_session_scope() as db:
                from sqlalchemy import func
                db_assets = (await db.execute(select(func.count(Asset.id)).where(Asset.scan_id == scan_id))).scalar() or 0
                db_urls = (await db.execute(select(func.count(URL.id)).join(Asset, URL.asset_id == Asset.id).where(Asset.scan_id == scan_id))).scalar() or 0
                db_findings = (await db.execute(select(func.count(Finding.id)).where(Finding.scan_id == scan_id))).scalar() or 0

            # Scan is only degraded if critical core discovery produced 0 assets or unhandled fatal failure aborted execution
            is_fatal_failure = any(f.get("fatal", False) for f in phase_failures)
            is_degraded = is_fatal_failure or (db_assets == 0 and any(f.get("phase") == "discovery" for f in phase_failures))
            completion_status = "degraded" if is_degraded else "completed"

            await ctx.emit(
                "pipeline.stage",
                (
                    f"Assessment completed for {root_domain}. Security report compiled ({db_assets} active assets, {db_urls} endpoints, {db_findings} findings)."
                    if not is_degraded
                    else f"Assessment finished in DEGRADED state for {root_domain}; critical reconnaissance phases were incomplete."
                ),
                stage="REPORT",
                tool="dossier_builder",
                progress=100,
                severity="warn" if is_degraded else "info",
            )
            await self._complete(
                scan_id,
                root_domain,
                status=completion_status,
                coverage_failures=phase_failures,
            )
        except asyncio.CancelledError:
            if not self._stop_flags.get(scan_id):
                raise
            try:
                from app.core.security_engine import security_engine
                security_engine.complete_scan(scan_id)
            except Exception:
                pass
            await self._finish_status(scan_id, "stopped")
            await event_bus.publish(result_service.make_event(
                scan_id, "scan.stopped", "Scan stopped by operator", severity="warn"))
        except Exception as exc:
            logger.exception("pipeline failed for %s", scan_id)
            await self._finish_status(scan_id, "failed")
            await event_bus.publish(result_service.make_event(
                scan_id, "scan.failed", f"Scan error: {exc}", severity="error"))
        finally:
            if val_stop_event is not None:
                val_stop_event.set()
            if val_worker_task is not None and not val_worker_task.done():
                val_worker_task.cancel()
                try:
                    await val_worker_task
                except asyncio.CancelledError:
                    pass
                except Exception as worker_err:
                    logger.debug("Validation worker cleanup error for %s: %s", scan_id, worker_err)
            if session_ctx is not None:
                try:
                    await session_ctx.close()
                except Exception as session_err:
                    logger.debug("Session cleanup error for %s: %s", scan_id, session_err)
            self._running.pop(scan_id, None)
            self._pause_events.pop(scan_id, None)
            self._stop_flags.pop(scan_id, None)

    async def _checkpoint(self, ctx: Any, db, root_domain: str, start_time: float) -> None:
        if kill_switch_manager.is_stopped(ctx.scan_id):
            raise asyncio.CancelledError("Campaign halted by kill switch")
        pause_ev = self._pause_events.get(ctx.scan_id)
        if pause_ev and not pause_ev.is_set():
            while not pause_ev.is_set():
                await asyncio.sleep(0.5)
        if time.time() - start_time > settings.max_runtime_minutes * 60:
            raise RuntimeError("Max scan runtime exceeded")
        count = (await db.execute(
            select(func.count()).select_from(Asset).where(Asset.scan_id == ctx.scan_id)
        )).scalar() or 0
        if count >= settings.max_assets_per_scan:
            raise RuntimeError("Max assets limit reached")

        # Persistent Checkpointing: serialize active opportunity bus state to database Scan entity
        try:
            from app.orchestration.attack_opportunity import opportunity_bus, OpportunityState
            from app.models.models import Scan
            scan = await db.get(Scan, ctx.scan_id)
            if scan:
                # Only checkpoint active/pending opportunities to save RAM/CPU and reduce DB write size
                active_states = {OpportunityState.QUEUED, OpportunityState.SUSPECTED, OpportunityState.VALIDATING}
                opps_to_save = [
                    opp.to_dict() for opp in opportunity_bus.get_all_opportunities()
                    if opp.state in active_states
                ]
                # Cap the checkpoint sizes to prevent SQLite write locking under high load
                opps_to_save = sorted(opps_to_save, key=lambda x: x.get("priority", 50), reverse=True)[:300]
                
                scan.checkpoint = {
                    "timestamp": time.time(),
                    "elapsed_seconds": time.time() - start_time,
                    "opportunities": opps_to_save,
                    "seen_fingerprints": list(opportunity_bus._seen_fingerprints)[:1000],
                }
                await db.commit()
                logger.info("Scan checkpoint persisted successfully for scan %s (%d active opportunities).", ctx.scan_id, len(opps_to_save))
        except Exception as err:
            logger.warning("Failed to persist scan checkpoint: %s", err)

    async def _set_status(self, scan_id: str, status: str, started_at: bool = False) -> None:
        async with async_session_scope() as db:
            scan = await db.get(Scan, scan_id)
            if scan:
                scan.status = status
                if started_at:
                    scan.started_at = scan.started_at or datetime.now(timezone.utc)
                await db.commit()

    async def _finish_status(self, scan_id: str, status: str) -> None:
        async with async_session_scope() as db:
            scan = await db.get(Scan, scan_id)
            if scan:
                scan.status = status
                scan.completed_at = datetime.now(timezone.utc)
                await db.commit()

    async def _complete(
        self,
        scan_id: str,
        root_domain: str,
        *,
        status: str = "completed",
        coverage_failures: Optional[list[dict[str, str]]] = None,
    ) -> None:
        async with async_session_scope() as db:
            scan = await db.get(Scan, scan_id)
            if not scan:
                return
            assets = (await db.execute(select(func.count()).select_from(Asset).where(Asset.scan_id == scan_id))).scalar() or 0
            asset_ids = select(Asset.id).where(Asset.scan_id == scan_id)
            urls = (await db.execute(select(func.count()).select_from(URL).where(URL.asset_id.in_(asset_ids)))).scalar() or 0
            ports = (await db.execute(select(func.count()).select_from(Port).where(Port.asset_id.in_(asset_ids)))).scalar() or 0
            params = (await db.execute(select(func.count()).select_from(Parameter).where(Parameter.url_id.in_(select(URL.id).where(URL.asset_id.in_(asset_ids)))))).scalar() or 0
            techs = (await db.execute(select(func.count()).select_from(Technology).where(Technology.asset_id.in_(asset_ids)))).scalar() or 0
            certs = (await db.execute(select(func.count()).select_from(Certificate).where(Certificate.asset_id.in_(asset_ids)))).scalar() or 0
            findings = (await db.execute(select(func.count()).select_from(Finding).where(Finding.scan_id == scan_id))).scalar() or 0
            screenshots_count = (await db.execute(select(func.count()).select_from(Screenshot).where(Screenshot.scan_id == scan_id))).scalar() or 0

            scan.status = status
            scan.completed_at = datetime.now(timezone.utc)
            scan.progress = {
                "assets": assets,
                "urls": urls,
                "ports": ports,
                "parameters": params,
                "technologies": techs,
                "certificates": certs,
                "findings": findings,
                "screenshots": screenshots_count,
                "coverage_complete": not coverage_failures,
                "coverage_failures": coverage_failures or [],
            }

            # Update Domain entity overview (§36)
            domain_entity = (await db.execute(select(Domain).where(Domain.name == root_domain))).scalar_one_or_none()
            if domain_entity:
                domain_entity.total_assets = assets
                domain_entity.total_findings = findings
                domain_entity.last_scanned = datetime.now(timezone.utc)
                if findings > 0:
                    domain_entity.risk_level = "HIGH" if findings > 3 else "MEDIUM"
                else:
                    domain_entity.risk_level = "LOW"

            await db.commit()

        event_type = "scan.completed" if status == "completed" else "scan.degraded"
        await event_bus.publish(result_service.make_event(
            scan_id, event_type, f"Scan {status} for {root_domain}",
            assets=assets, urls=urls, ports=ports, parameters=params, technologies=techs,
            certificates=certs, findings=findings,
            coverage_failures=coverage_failures or [],
            severity="success" if status == "completed" else "warn"))

    async def _run_continuous_validation_worker(
        self,
        ctx: Any,
        scan_id: str,
        root_domain: str,
        session: SessionContext,
        stop_event: asyncio.Event,
    ) -> None:
        """Continuously consumes opportunities from OpportunityBus and executes specialist attack modules."""
        logger.info("Continuous validation worker active for scan %s", scan_id)
        while not stop_event.is_set() or opportunity_bus.get_queue_size() > 0:
            if kill_switch_manager.is_stopped(scan_id):
                break

            opp = await opportunity_bus.get_next(timeout=1.0)
            if not opp:
                if stop_event.is_set():
                    break
                continue

            try:
                module = get_attack_module(opp.attack_type)
                if not module:
                    opportunity_bus.task_done()
                    continue

                # Execute attack module
                res = await module.validate(opp, session)
                if res.is_vulnerable:
                    ev_pkg = await module.collect_evidence(res)
                    risk = await module.score(ev_pkg, res)

                    await opportunity_bus.update_state(
                        opp.id,
                        OpportunityState.CONFIRMED,
                        evidence=ev_pkg.to_dict(),
                        message=res.message,
                    )

                    # Persist confirmed finding to database
                    async with async_session_scope() as db:
                        host_label = opp.host or root_domain
                        asset = (await db.execute(
                            select(Asset).where(Asset.scan_id == scan_id, Asset.hostname == host_label)
                        )).scalar_one_or_none()

                        asset_id = asset.id if asset else None
                        finding_type = f"{opp.attack_type}_vulnerability"

                        # Determine evidence level based on exploitation depth
                        expl_data = getattr(res, 'exploitation_data', {}) or {}
                        has_deep_proof = bool(expl_data)
                        ev_level = "E4" if has_deep_proof else "E3"
                        ev_score = 95 if has_deep_proof else 90

                        # Merge exploitation_data into evidence package
                        evidence_dict = ev_pkg.to_dict()
                        if expl_data:
                            evidence_dict["exploitation_data"] = expl_data

                        await result_service.upsert_finding(
                            db,
                            scan_id=scan_id,
                            asset_id=asset_id,
                            finding_type=finding_type,
                            title=f"Confirmed {opp.attack_type.upper()} on {opp.endpoint}",
                            severity=res.severity,
                            confidence="CONFIRMED",
                            cwe_id=res.cwe_id,
                            cvss_score=risk.cvss_v4,
                            description=res.message,
                            impact=risk.impact,
                            technical_details=f"PoC: {res.poc_curl}\n\nEvidence: {res.evidence}",
                            remediation=f"Sanitize and validate input on {opp.parameter or 'endpoint'} and follow standard remediation guidelines for {res.cwe_id}.",
                            evidence_level=ev_level,
                            evidence_score=ev_score,
                            exploitability_state="EXPLOITABLE",
                            priority="P1" if res.severity in ("CRITICAL", "HIGH") else "P2",
                            evidence_data=evidence_dict,
                            poc_curl=res.poc_curl,
                            poc_valid=True,
                            matched_at=opp.endpoint,
                        )
                        await db.commit()

                    # Emit real-time telemetry event
                    await ctx.emit(
                        "finding.confirmed",
                        f"🚨 {res.severity} CONFIRMED: {opp.attack_type.upper()} on {opp.endpoint} - {res.message}",
                        severity="error" if res.severity in ("CRITICAL", "HIGH") else "warn",
                        finding_type=opp.attack_type,
                        url=opp.endpoint,
                        poc_curl=res.poc_curl,
                    )

                    # Attack Chaining: If credentials discovered in artifact, link and synthesize new attack opportunities
                    if opp.attack_type == "artifact" and "extracted_secrets" in res.evidence:
                        for k, v in res.evidence["extracted_secrets"].items():
                            attack_graph_engine.add_credential_discovery(
                                source_finding_id=opp.id,
                                username=k,
                                password_or_token=v,
                                secret_type=k,
                                target_url=opp.endpoint,
                            )
                        chained_opps = attack_graph_engine.generate_chained_opportunities()
                        await opportunity_bus.publish_batch(chained_opps)

                else:
                    await opportunity_bus.update_state(
                        opp.id,
                        OpportunityState.INCONCLUSIVE if res.confidence > 0.3 else OpportunityState.REJECTED,
                        message=res.message,
                    )

            except Exception as opp_err:
                logger.debug("Error in continuous validation on opp %s: %s", opp.id, opp_err)
            finally:
                opportunity_bus.task_done()



class ScanContextPort:
    def __init__(self, scan_id: str, scope: ScopeEngine, profile: str, options: Dict[str, Any], limiter: RateLimiter):
        self.scan_id = scan_id
        self.scope = scope
        self.profile = profile
        self.options = options
        self.rate_limiter = limiter

    async def emit(self, event_type: str, message: str, **data) -> None:
        ev = result_service.make_event(self.scan_id, event_type, message, **data)
        await event_bus.publish(ev)


scan_manager = ScanManager()
