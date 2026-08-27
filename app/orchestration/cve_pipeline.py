"""CVE-Driven Port-to-Immediate-Pentest Pipeline (V15).

Implements:
1. Immediate analysis upon port discovery.
2. Version-aware CVE correlation and applicability analysis.
3. Extensible service validators invocation.
4. Active, evidence-driven validation.
5. Integration with database findings and attack graph.
6. Parallel background execution.
"""

from __future__ import annotations

import logging
import asyncio
from typing import Any, Dict, List, Optional, Sequence

from app.core.config import settings
from app.core.resource_governor import resource_governor
from app.core.session_context import SessionContext
from app.scanners.base import ScanContext
from app.validation.service_validators import get_service_validator, service_validator_registry
from app.attacks.base import ValidationResult
from app.core.db import AsyncSessionLocal
from app.services.results import result_service
from app.models.models import Port, Service
from app.intelligence.attack_graph import attack_graph_engine
from app.orchestration.attack_opportunity import AttackOpportunity, opportunity_bus

logger = logging.getLogger("orchestration.cve_pipeline")

HIGH_RISK_NSE_PORTS = {
    21, 22, 23, 25, 80, 139, 443, 445, 1433, 3306, 3389, 8080, 8443,
}


async def trigger_host_nmap_vuln_pipeline(
    ctx: ScanContext,
    asset_id: str,
    host: str,
    ports: Sequence[int],
) -> Dict[str, Any]:
    """Run one bounded, safe NSE scan per host and persist confirmed script results."""
    option = ctx.options.get("nmap_vuln_scan")
    enabled = (
        bool(option)
        if option is not None
        else settings.nmap_vuln_enabled or ctx.profile == "adversary_simulation"
    )
    if not enabled:
        return {"status": "disabled", "findings": []}
    if not ctx.scope.host_allowed(host):
        return {"status": "blocked", "error": "Target is outside authorized scope", "findings": []}
    if not resource_governor.should_admit_task(is_high_priority=True):
        await ctx.emit(
            "scan.throttled",
            f"Nmap vulnerability checks deferred for {host}: resource pressure is high.",
            host=host,
            severity="warn",
        )
        return {"status": "throttled", "findings": []}

    selected_ports = sorted({int(p) for p in ports if int(p) in HIGH_RISK_NSE_PORTS})
    selected_ports = selected_ports[: max(1, settings.nmap_vuln_max_ports)]
    if not selected_ports:
        return {"status": "skipped", "findings": []}

    from app.adapters.tools.nmap_adapter import NmapAdapter

    adapter = NmapAdapter()
    if not await adapter.healthcheck():
        return {"status": "unavailable", "error": "Nmap binary not found", "findings": []}

    ports_csv = ",".join(str(port) for port in selected_ports)
    await ctx.emit(
        "scan.cve",
        f"Running bounded safe NSE checks on {host} ports {ports_csv}.",
        host=host,
        ports=selected_ports,
    )
    result = await adapter.execute_vuln_scan(host, ports_csv)
    if result.get("status") != "success":
        await ctx.emit(
            "scan.cve.warning",
            f"Nmap NSE checks on {host} ended with status {result.get('status', 'error')}.",
            host=host,
            error=result.get("error", ""),
            severity="warn",
        )
        return result

    async with AsyncSessionLocal() as db:
        for item in result.get("findings", []):
            cves = item.get("cves") or []
            finding = await result_service.upsert_finding(
                db,
                scan_id=ctx.scan_id,
                asset_id=asset_id,
                finding_type="nmap_script_vuln",
                title=(
                    f"Nmap NSE: {item.get('script_id', 'vuln')} on "
                    f"{host}:{item.get('port', 'unknown')}"
                ),
                severity=item.get("severity", "MEDIUM"),
                confidence="CONFIRMED",
                cve_id=cves[0] if cves else None,
                description=(
                    "A non-destructive Nmap NSE script returned an explicit VULNERABLE state. "
                    "Review the captured script output and independently confirm remediation."
                ),
                evidence={
                    "nmap_output": item.get("output", "")[:16000],
                    "script_id": item.get("script_id", ""),
                    "service": item.get("service", "unknown"),
                    "port": item.get("port"),
                    "cves": cves,
                },
                poc_command=(
                    f"nmap -sV -p {item.get('port')} --script 'vuln and safe' {host}"
                ),
                exploitability_state="VALIDATED",
            )
            if finding:
                await ctx.emit(
                    "port.vulnerability",
                    f"NSE validation confirmed: {finding.title}",
                    host=host,
                    port=item.get("port"),
                    cve_id=cves[0] if cves else None,
                    severity=item.get("severity", "MEDIUM"),
                )
        await db.commit()
    return result


async def trigger_immediate_cve_pipeline(
    ctx: ScanContext,
    asset_id: str,
    host: str,
    ip: Optional[str],
    port: int,
):
    """Executes the complete service discovery to active validation pipeline in the background."""
    session: Optional[SessionContext] = None
    try:
        if not ctx.scope.host_allowed(host) or not ctx.scope.port_allowed(port):
            logger.warning("Blocked out-of-scope service validation for %s:%d", host, port)
            return
        if not resource_governor.should_admit_task(is_high_priority=True):
            logger.info("Resource pressure blocked service validation for %s:%d", host, port)
            return

        from app.scanners.port import COMMON_PORTS, _grab_banner
        
        # 1. Service Identification
        banner = await _grab_banner(host, port, timeout=1.5)
        service_name = COMMON_PORTS.get(port, "unknown")
        
        # 2. Lookup Extensible Service Validator
        validator = get_service_validator(service_name)
        if not validator:
            from app.intelligence.service_profiles import ServiceProfileRegistry
            profile = ServiceProfileRegistry.find_profile_for_port(port)
            if profile:
                validator = get_service_validator(profile.name)

        if not validator:
            logger.debug("No validator registered for service %s on port %d", service_name, port)
            return

        # 3. Product / Version Fingerprinting
        step_timeout = max(5.0, min(30.0, settings.http_timeout_seconds * 3))
        fp = await asyncio.wait_for(
            validator.fingerprint(host, port, banner), timeout=step_timeout
        )
        product = fp.get("product") or validator.name
        version = await asyncio.wait_for(
            validator.identify_version(host, port, banner), timeout=step_timeout
        )
        
        service_info = {
            "product": product,
            "version": version,
            "banner": banner,
            "port": port,
        }

        # Save Port & Service records immediately to db
        async with AsyncSessionLocal() as db:
            from sqlalchemy import select
            port_rec = (await db.execute(
                select(Port).where(Port.asset_id == asset_id, Port.port == port, Port.protocol == "tcp")
            )).scalar_one_or_none()
            if not port_rec:
                port_rec = Port(
                    asset_id=asset_id,
                    ip=ip,
                    port=port,
                    protocol="tcp",
                    state="open",
                    service=service_name,
                    banner=banner,
                )
                db.add(port_rec)
                await db.flush()
            else:
                port_rec.state = "open"
                if banner:
                    port_rec.banner = banner

            svc_rec = (await db.execute(
                select(Service).where(Service.asset_id == asset_id, Service.port_id == port_rec.id)
            )).scalar_one_or_none()
            if not svc_rec:
                is_tls = port in (443, 8443, 2083, 2087, 2096, 993, 995, 8883, 5986, 6443, 2376, 10443, 4433, 4443)
                svc_rec = Service(
                    asset_id=asset_id,
                    port_id=port_rec.id,
                    name=service_name,
                    protocol="tcp",
                    tls_enabled=is_tls,
                    banner=banner,
                    product=product,
                    version=version,
                    metadata_={"port": port, "banner": banner},
                )
                db.add(svc_rec)
            else:
                svc_rec.product = product
                svc_rec.version = version
                if banner:
                    svc_rec.banner = banner
            await db.commit()

        # 4. Generate Opportunities (includes version CVEs & configuration checks)
        opps = await asyncio.wait_for(
            validator.generate_opportunities(host, port, service_info), timeout=step_timeout
        )

        session = SessionContext(base_url=f"http://{host}:{port}", rate_limiter=ctx.rate_limiter)

        # 5. Immediate Active Validation
        for opp in opps[:12]:
            try:
                result = await asyncio.wait_for(
                    validator.validate(opp, session), timeout=step_timeout
                )
                
                # 6. Evidence Collection
                if result.is_vulnerable:
                    async with AsyncSessionLocal() as db:
                        # Save vulnerability finding
                        finding = await result_service.upsert_finding(
                            db,
                            scan_id=ctx.scan_id,
                            asset_id=asset_id,
                            finding_type=result.attack_type,
                            title=result.message or f"{opp.metadata.get('cve_id', 'Vulnerability')} on {host}:{port}",
                            severity=result.severity,
                            confidence="CONFIRMED" if result.confidence >= 0.8 else "VALIDATED",
                            cwe_id=result.cwe_id,
                            cve_id=opp.metadata.get("cve_id"),
                            description=result.message,
                            evidence=result.evidence,
                            poc_command=result.poc_curl,
                            exploitability_state="CONFIRMED" if result.proof_level in ("P3", "P4") else "APPLICABLE",
                        )
                        await db.commit()
                        
                    if finding:
                        # 7. Integrate with Attack Graph
                        attack_graph_engine.add_node(
                            node_id=finding.id,
                            node_type="Finding",
                            label=finding.title,
                            url=opp.target,
                        )
                        
                        # 8. Continue attacking / Next Attack Opportunity
                        # If credentials found, register them in attack graph & generate login portal testing tasks
                        creds_list = result.evidence.get("credentials")
                        if creds_list:
                            for uname, passwd in creds_list:
                                attack_graph_engine.add_credential_discovery(
                                    source_finding_id=finding.id,
                                    username=uname,
                                    password_or_token=passwd,
                                    secret_type="database_password" if service_name in ("mysql", "postgresql") else "user_password",
                                    target_url=opp.target,
                                )
                            chained_opps = attack_graph_engine.generate_chained_opportunities()
                            await opportunity_bus.publish_batch(chained_opps)

                        # Emit real-time vulnerability event
                        await ctx.emit(
                            "port.vulnerability",
                            f"VULNERABLE: {result.message}",
                            host=host,
                            port=port,
                            cve_id=opp.metadata.get("cve_id"),
                            severity=result.severity,
                        )
            except Exception as val_err:
                logger.error("Validation failed for opportunity %s on %s:%d: %s", opp.hypothesis, host, port, val_err, exc_info=True)
    except Exception as exc:
        logger.error("Error running immediate CVE pipeline on %s:%d: %s", host, port, exc, exc_info=True)
    finally:
        if session is not None:
            await session.close()
