from __future__ import annotations

import asyncio
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import func, select

from app.core.config import settings
from app.core.db import AsyncSessionLocal, async_session_scope
from app.core.events import event_bus
from app.core.kill_switch import kill_switch_manager
from app.core.rate_limit import RateLimiter
from app.core.scope_engine import ScopeEngine, normalize_target
from app.models.models import Asset, Certificate, Domain, Finding, Parameter, Port, Scan, Screenshot, Technology, URL
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
        profile: str = "standard",
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
        prof = (str(profile) if profile is not None else "standard").lower().strip()
        valid_profiles = (
            AssessmentProfile.BUG_HUNT,
            AssessmentProfile.DEEP_BUG_HUNT,
            AssessmentProfile.PENTEST,
            AssessmentProfile.ADVERSARY_SIMULATION,
            "quick",
            "standard",
            "deep",
            "deep_bug_hunt",
            "pentest",
            "adversary_simulation",
            "full",
            "aggressive",
            "passive",
            "custom",
        )
        if prof not in valid_profiles:
            prof = "standard"

        # Defensive handling if callers swapped include_subdomains and validation_level
        if isinstance(include_subdomains, str) and validation_level is None:
            validation_level = include_subdomains
            include_subdomains = True
        elif isinstance(validation_level, bool):
            include_subdomains = validation_level
            validation_level = None

        # Auto-map validation levels
        if validation_level and isinstance(validation_level, str):
            val_level = validation_level.upper().strip()
        else:
            val_level = ""

        if val_level not in ValidationLevel.ALL_LEVELS:
            if prof in (AssessmentProfile.ADVERSARY_SIMULATION, "adversary_simulation", "full", "aggressive", "max"):
                val_level = ValidationLevel.L4_HIGH_RISK
            elif prof in (AssessmentProfile.PENTEST, AssessmentProfile.DEEP_BUG_HUNT, "deep", "deep_bug_hunt", "pentest"):
                val_level = ValidationLevel.L4_HIGH_RISK  # Full aggressive capabilities without restriction
            elif prof in ("passive", "osint"):
                val_level = ValidationLevel.L1_PASSIVE
            elif prof == "observe":
                val_level = ValidationLevel.L0_OBSERVE
            else:
                val_level = ValidationLevel.L2_SAFE_ACTIVE

        is_aggressive = val_level in (ValidationLevel.L3_CONTROLLED, ValidationLevel.L4_HIGH_RISK)

        options: Dict[str, Any] = {
            "port_scan": prof != "passive",
            "web_discovery": prof not in ("passive", "quick"),
            "parameter_discovery": prof not in ("passive", "quick"),
            "security_checks": prof != "passive",
            "deep_crawl": is_aggressive,
            "deep_parameter_fuzzing": is_aggressive,
            "js_analysis": is_aggressive,
            "include_subdomains": include_subdomains,
            "target_host": host,
            "target_url": target if "://" in target else f"http://{target}",
            "max_assets": settings.max_assets_per_scan,
            "max_urls": settings.max_urls_per_scan,
            "max_runtime_seconds": settings.max_runtime_minutes * 60,
            "validation_level": val_level,
        }

        scan_id = f"scan_{int(time.time())}_{uuid.uuid4().hex[:6]}_{host.replace('.', '_')}"
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
                profile=prof,
                validation_level=val_level,
                options=options,
                authorization_id=authorization_id,
                authorization_reference=authorization_reference or authorization_id,
                allowed_modules=allowed_modules or [],
                allowed_actions=allowed_actions or [],
            )
            db.add(scan)
            await db.commit()

        await event_bus.publish(result_service.make_event(
            scan_id, "scan.started", f"Scan queued for {root_domain} [Profile: {prof.upper()}, Level: {val_level}]",
            target=root_domain, profile=prof, validation_level=val_level, severity="info"))
        self._run(scan_id, root_domain, prof, options)
        return {
            "scan_id": scan_id,
            "campaign_id": camp_id,
            "status": "queued",
            "target": root_domain,
            "profile": prof,
            "validation_level": val_level,
        }

    def _run(self, scan_id: str, root_domain: str, profile: str, options: Dict[str, Any]) -> None:
        if scan_id in self._running:
            return
        ev = asyncio.Event()
        ev.set()
        self._pause_events[scan_id] = ev
        self._stop_flags[scan_id] = False
        task = asyncio.create_task(self._pipeline(scan_id, root_domain, profile, options))
        self._running[scan_id] = task

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
            scope = ScopeEngine(target_host, allowed_hosts=[target_host], recursive=False)
        else:
            scope = ScopeEngine(root_domain, recursive=True)

        limiter = RateLimiter(settings.rate_limit_rps)
        ctx = ScanContext(scan_id, scope, profile, options, limiter)

        start_time = time.time()
        try:
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
                if options.get("port_scan", True) and profile != "passive" and not kill_switch_manager.is_stopped(scan_id, "network"):
                    try:
                        async with async_session_scope() as db:
                            await self._checkpoint(ctx, db, root_domain, start_time)
                            await port.run(ctx, db, root_domain)
                    except Exception as phase_err:
                        logger.warning("Port scan phase warning on %s: %s", scan_id, phase_err)

            async def run_http():
                if not kill_switch_manager.is_stopped(scan_id, "web"):
                    try:
                        async with async_session_scope() as db:
                            await self._checkpoint(ctx, db, root_domain, start_time)
                            await http.run(ctx, db, root_domain)
                    except Exception as phase_err:
                        logger.warning("HTTP probe phase warning on %s: %s", scan_id, phase_err)

            await asyncio.gather(run_port(), run_http())

            try:
                from app.intelligence.llm_client import llm_client
                from app.models.models import Asset, Port, URL, Technology

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
            if options.get("web_discovery", True) and profile not in ("passive", "quick") and not kill_switch_manager.is_stopped(scan_id, "crawler"):
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

                    # Update application model with discovered endpoints
                    app_model = security_engine.get_app_model(scan_id)
                    reasoning = security_engine.get_reasoning_layer(scan_id)
                    if app_model:
                        async with async_session_scope() as db:
                            urls_res = await db.execute(
                                select(URL).join(Asset, URL.asset_id == Asset.id).where(Asset.scan_id == scan_id).limit(60)
                            )
                            for u in urls_res.scalars().all():
                                app_model.add_entity(
                                    entity_type=EntityType.ENDPOINT,
                                    label=u.path or u.url or "/",
                                    properties={"url": u.url, "method": u.method or "GET"}
                                )
                        # Re-run reasoning cycle with new endpoint data
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

            # ---- Phase E: Security intelligence & deep validation ----
            if options.get("security_checks", True) and profile != "passive" and not kill_switch_manager.is_stopped(scan_id, "validation"):
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

            try:
                security_engine.start_validation(scan_id)
            except Exception as se_err:
                logger.debug("SecurityEngine start_validation: %s", se_err)

            # ---- Phase F: Automated Visual Evidence & Screenshot Worker (V4 §10) ----
            if profile != "passive" and not kill_switch_manager.is_stopped(scan_id, "browser"):
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

            try:
                security_engine.start_reporting(scan_id)
                security_engine.complete_scan(scan_id)
            except Exception as se_err:
                logger.debug("SecurityEngine complete_scan: %s", se_err)

            # ---- Complete Scan & Update Summary ----
            await ctx.emit(
                "pipeline.stage",
                f"🎉 Pentest completed for {root_domain}. Security report compiled.",
                stage="REPORT",
                tool="dossier_builder",
                progress=100,
                severity="info",
            )
            await self._complete(scan_id, root_domain)
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
            await self._finish_status(scan_id, "partial_failure")
            await event_bus.publish(result_service.make_event(
                scan_id, "scan.failed", f"Scan error: {exc}", severity="error"))
        finally:
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

    async def _complete(self, scan_id: str, root_domain: str) -> None:
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

            scan.status = "completed"
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

        await event_bus.publish(result_service.make_event(
            scan_id, "scan.completed", f"Scan completed for {root_domain}",
            assets=assets, urls=urls, ports=ports, parameters=params, technologies=techs,
            certificates=certs, findings=findings, severity="success"))


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