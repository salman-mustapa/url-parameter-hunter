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
from typing import Any, Dict, List, Optional

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


async def trigger_immediate_cve_pipeline(
    ctx: ScanContext,
    asset_id: str,
    host: str,
    ip: Optional[str],
    port: int,
):
    """Executes the complete service discovery to active validation pipeline in the background."""
    try:
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
        fp = await validator.fingerprint(host, port, banner)
        product = fp.get("product") or validator.name
        version = await validator.identify_version(host, port, banner)
        
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
        opps = await validator.generate_opportunities(host, port, service_info)
        
        session = SessionContext(base_url=f"http://{host}:{port}")

        # 5. Immediate Active Validation
        for opp in opps:
            try:
                result = await validator.validate(opp, session)
                
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
                            confidence=f"{result.confidence:.2f}",
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
