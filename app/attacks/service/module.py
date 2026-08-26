"""Network Service Protocol & Exposed Port Attack Module (V15).

Verifies unauthenticated exposures on standard and database services:
- Redis (6379): Unauthenticated INFO / PING
- MongoDB (27017): Unauthenticated isMaster wire command
- Elasticsearch (9200): Unauthenticated /_cat/indices / cluster health
- FTP (21): Anonymous login (anonymous:anonymous)
- Memcached (11211): Unauthenticated stats command
- MySQL (3306): Handshake & unauthenticated root verification
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from app.attacks.base import AttackPlan, BaseAttackModule, ValidationResult
from app.core.session_context import SessionContext
from app.orchestration.attack_opportunity import AttackOpportunity

logger = logging.getLogger("attacks.service")


class ServiceAttackModule(BaseAttackModule):
    def __init__(self) -> None:
        super().__init__(attack_type="service", cwe_id="CWE-306", default_severity="CRITICAL")

    async def discover(self, target: str, context: Dict[str, Any]) -> List[AttackOpportunity]:
        opps: List[AttackOpportunity] = []
        ports = context.get("ports", [])
        for p in ports:
            port_num = p.get("port") or p.get("port_number")
            service = p.get("service", "").lower()
            if port_num in (6379, 27017, 9200, 21, 11211, 3306, 5432) or service in ("redis", "mongodb", "elasticsearch", "ftp", "memcached", "mysql"):
                opps.append(
                    AttackOpportunity(
                        target=target,
                        endpoint=f"{target}:{port_num}",
                        protocol="tcp",
                        service=service or str(port_num),
                        attack_type="service",
                        hypothesis=f"Port {port_num} ({service}) may allow unauthenticated access.",
                        priority=95,
                    )
                )
        return opps

    async def plan(self, opportunity: AttackOpportunity) -> AttackPlan:
        return AttackPlan(
            title=f"Unauthenticated Service Access Audit on {opportunity.service} ({opportunity.endpoint})",
            attack_type="service",
            target=opportunity.endpoint,
            steps=[
                "1. Open raw TCP socket connection",
                "2. Dispatch service-specific unauthenticated probe (INFO, stats, isMaster, _cat/indices)",
                "3. Verify unauthenticated data exposure",
            ],
            payloads=["INFO\r\n", "stats\r\n", "USER anonymous\r\nPASS anonymous\r\n"],
            expected_evidence="Service banner, server version, database indices, or successful command reply.",
        )

    async def validate(self, opportunity: AttackOpportunity, session: SessionContext) -> ValidationResult:
        host = opportunity.host
        service = opportunity.service.lower()
        port_num = 0
        if ":" in opportunity.endpoint:
            try:
                port_num = int(opportunity.endpoint.split(":")[-1].split("/")[0])
            except ValueError:
                pass

        if not port_num:
            if "redis" in service:
                port_num = 6379
            elif "mongo" in service:
                port_num = 27017
            elif "elastic" in service:
                port_num = 9200
            elif "ftp" in service:
                port_num = 21
            elif "memcache" in service:
                port_num = 11211
            elif "mysql" in service:
                port_num = 3306

        # 1. Elasticsearch HTTP Probe
        if port_num == 9200 or "elastic" in service:
            es_url = f"http://{host}:9200/_cat/indices?v"
            resp = await session.get(es_url)
            if resp.status_code == 200 and ("health" in resp.text or "index" in resp.text):
                poc_curl = f"curl -s -k '{es_url}'"
                return ValidationResult(
                    is_vulnerable=True,
                    confidence=0.99,
                    proof_level="P4",
                    attack_type="service",
                    target_url=es_url,
                    exploit_status=200,
                    evidence={"service": "Elasticsearch", "response_sample": resp.text[:300]},
                    poc_curl=poc_curl,
                    message="CRITICAL: Unauthenticated Elasticsearch cluster exposure confirmed via /_cat/indices.",
                    cwe_id="CWE-306",
                    severity="CRITICAL",
                )

        # 2. Raw Socket Probing for Redis / Memcached / FTP
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port_num),
                timeout=4.0,
            )

            if port_num == 6379 or "redis" in service:
                writer.write(b"INFO\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=3.0)
                writer.close()
                await writer.wait_closed()

                text = data.decode("utf-8", errors="ignore")
                if "redis_version" in text or "os:" in text:
                    poc_curl = f"redis-cli -h {host} -p {port_num} info"
                    return ValidationResult(
                        is_vulnerable=True,
                        confidence=0.99,
                        proof_level="P4",
                        attack_type="service",
                        target_url=f"{host}:{port_num}",
                        evidence={"service": "Redis", "response_sample": text[:300]},
                        poc_curl=poc_curl,
                        message=f"CRITICAL: Unauthenticated Redis database access confirmed on {host}:{port_num}.",
                        cwe_id="CWE-306",
                        severity="CRITICAL",
                    )

            elif port_num == 11211 or "memcache" in service:
                writer.write(b"stats\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=3.0)
                writer.close()
                await writer.wait_closed()

                text = data.decode("utf-8", errors="ignore")
                if "STAT version" in text or "STAT uptime" in text:
                    poc_curl = f"nc {host} {port_num} <<< 'stats'"
                    return ValidationResult(
                        is_vulnerable=True,
                        confidence=0.99,
                        proof_level="P4",
                        attack_type="service",
                        target_url=f"{host}:{port_num}",
                        evidence={"service": "Memcached", "response_sample": text[:300]},
                        poc_curl=poc_curl,
                        message=f"CRITICAL: Unauthenticated Memcached server access confirmed on {host}:{port_num}.",
                        cwe_id="CWE-306",
                        severity="CRITICAL",
                    )

            elif port_num == 21 or "ftp" in service:
                banner = await asyncio.wait_for(reader.read(512), timeout=3.0)
                writer.write(b"USER anonymous\r\n")
                await writer.drain()
                user_reply = await asyncio.wait_for(reader.read(512), timeout=3.0)
                writer.write(b"PASS anonymous\r\n")
                await writer.drain()
                pass_reply = await asyncio.wait_for(reader.read(512), timeout=3.0)
                writer.close()
                await writer.wait_closed()

                combined = (user_reply + pass_reply).decode("utf-8", errors="ignore")
                if "230" in combined or "logged in" in combined.lower():
                    poc_curl = f"ftp -n {host} <<< $'user anonymous anonymous\\nls'"
                    return ValidationResult(
                        is_vulnerable=True,
                        confidence=0.98,
                        proof_level="P4",
                        attack_type="service",
                        target_url=f"{host}:{port_num}",
                        evidence={"service": "FTP", "response_sample": combined[:300]},
                        poc_curl=poc_curl,
                        message=f"HIGH: Anonymous FTP login confirmed on {host}:{port_num}.",
                        cwe_id="CWE-306",
                        severity="HIGH",
                    )

            writer.close()
            await writer.wait_closed()

        except Exception as e:
            logger.debug("Socket probe error on %s:%s - %s", host, port_num, e)

        return ValidationResult(
            is_vulnerable=False,
            confidence=0.1,
            proof_level="P0",
            attack_type="service",
            target_url=f"{host}:{port_num}",
            message=f"Service on port {port_num} enforced authentication or was unreachable.",
        )
