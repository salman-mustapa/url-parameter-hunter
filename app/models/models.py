from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


def gen_uuid() -> str:
    return str(uuid.uuid4())


# ==========================================================================
# 1. Identity, Tenants, Users & Access Control (RBAC)
# ==========================================================================
class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    name: Mapped[str] = mapped_column(String, nullable=False, default="Default Organization")
    slug: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    tier: Mapped[str] = mapped_column(String, nullable=False, default="enterprise")  # free, pro, enterprise
    max_active_investigations: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    max_concurrent_tasks: Mapped[int] = mapped_column(Integer, nullable=False, default=25)
    max_rps: Mapped[int] = mapped_column(Integer, nullable=False, default=20)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    tenant_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("tenants.id", ondelete="set null"), index=True, nullable=True)
    username: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    email: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String, nullable=False)
    role: Mapped[str] = mapped_column(String, nullable=False, default="user")  # "user" or "admin"
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    tenant_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("tenants.id", ondelete="cascade"), index=True, nullable=True)
    user_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("users.id", ondelete="set null"), index=True, nullable=True)
    name: Mapped[str] = mapped_column(String, nullable=False, default="Default Project")
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ==========================================================================
# 2. Scope Engine (§2, §102)
# ==========================================================================
class ScopeModel(Base):
    __tablename__ = "scopes"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    name: Mapped[str] = mapped_column(String, nullable=False, default="Default Scope")
    root_domain: Mapped[str] = mapped_column(String, index=True, nullable=False)
    authorization_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    allowed_hosts: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    excluded_hosts: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    allowed_cidrs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    allowed_ports: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    allowed_modules: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    max_rate_rps: Mapped[int] = mapped_column(Integer, nullable=False, default=15)
    max_concurrency: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    is_recursive: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    expiry: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(String, ForeignKey("users.id", ondelete="set null"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ==========================================================================
# 3. Domain Entity (§5, §36)
# ==========================================================================
class Domain(Base):
    __tablename__ = "domains"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    name: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    health_status: Mapped[str] = mapped_column(String, nullable=False, default="ACTIVE")
    risk_level: Mapped[str] = mapped_column(String, nullable=False, default="LOW")
    total_assets: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_screenshots: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_scanned: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ==========================================================================
# 4. Scan Session & Campaign Orchestration (V8 §3, §5, §28, §43, V13 Multi-Tenant)
# ==========================================================================
class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    campaign_id: Mapped[Optional[str]] = mapped_column(String, index=True, nullable=True)
    tenant_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("tenants.id", ondelete="set null"), index=True, nullable=True)
    project_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("projects.id", ondelete="set null"), index=True, nullable=True)
    user_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("users.id", ondelete="set null"), index=True, nullable=True)
    scope_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("scopes.id", ondelete="set null"), index=True, nullable=True)
    domain_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("domains.id", ondelete="set null"), index=True, nullable=True)
    root_domain: Mapped[str] = mapped_column(String, index=True, nullable=False)
    status: Mapped[str] = mapped_column(String, index=True, nullable=False, default="created")  # created, queued, starting, running, paused, waiting, degraded, completed, failed, cancelled, recovering
    profile: Mapped[str] = mapped_column(String, nullable=False, default="standard")  # bug_hunt, deep_bug_hunt, pentest, adversary_simulation, quick, standard, deep, custom
    validation_level: Mapped[str] = mapped_column(String, nullable=False, default="L2_SAFE_ACTIVE")  # L0_OBSERVE, L1_PASSIVE, L2_SAFE_ACTIVE, L3_CONTROLLED, L4_HIGH_RISK
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    options: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    checkpoint: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    heartbeat_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    authorization_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    authorization_reference: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    operator_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    allowed_modules: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    allowed_actions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    active_module_status: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)  # per-module kill switch state
    kill_switch: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    progress: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class DurableTask(Base):
    __tablename__ = "durable_tasks"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id", ondelete="cascade"), index=True, nullable=False)
    tenant_id: Mapped[Optional[str]] = mapped_column(String, index=True, nullable=True)
    user_id: Mapped[Optional[str]] = mapped_column(String, index=True, nullable=True)
    task_type: Mapped[str] = mapped_column(String, index=True, nullable=False)
    target: Mapped[str] = mapped_column(String, nullable=False)
    state: Mapped[str] = mapped_column(String, index=True, nullable=False, default="PENDING")  # PENDING, READY, RUNNING, BLOCKED, PAUSED, COMPLETED, FAILED, RETRYING, CANCELLED, STALE, DEAD_LETTER
    idempotency_key: Mapped[str] = mapped_column(String, index=True, nullable=False)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    worker_id: Mapped[Optional[str]] = mapped_column(String, index=True, nullable=True)
    worker_class: Mapped[str] = mapped_column(String, nullable=False, default="worker-general")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    checkpoint: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    context_data: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    result: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error_type: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # TRANSIENT, PERMANENT
    heartbeat_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class DeadLetterTask(Base):
    __tablename__ = "dead_letter_tasks"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    task_id: Mapped[str] = mapped_column(String, index=True, nullable=False)
    scan_id: Mapped[str] = mapped_column(String, index=True, nullable=False)
    tenant_id: Mapped[Optional[str]] = mapped_column(String, index=True, nullable=True)
    task_type: Mapped[str] = mapped_column(String, nullable=False)
    target: Mapped[str] = mapped_column(String, nullable=False)
    worker_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    stack_trace: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class DeviceTrial(Base):
    __tablename__ = "device_trials"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    device_fingerprint: Mapped[str] = mapped_column(String, index=True, nullable=False)
    ip_address: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id", ondelete="cascade"), nullable=False)
    user_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("users.id", ondelete="set null"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ==========================================================================
# 5. Asset Graph (§5, §6, §11, §37)
# ==========================================================================
class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("scan_id", "asset_type", "fingerprint", name="uq_asset_scan_type_fp"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id", ondelete="cascade"), index=True, nullable=False)
    parent_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("assets.id", ondelete="set null"), nullable=True)
    domain_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("domains.id", ondelete="set null"), nullable=True)
    asset_type: Mapped[str] = mapped_column(String, index=True, nullable=False)  # domain, subdomain, ip, cidr
    fingerprint: Mapped[str] = mapped_column(String, index=True, nullable=False)
    hostname: Mapped[Optional[str]] = mapped_column(String, index=True, nullable=True)
    fqdn: Mapped[Optional[str]] = mapped_column(String, index=True, nullable=True)
    ip: Mapped[Optional[str]] = mapped_column(String, index=True, nullable=True)
    depth: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String, nullable=False, default="discovered")
    liveness_status: Mapped[str] = mapped_column(String, nullable=False, default="ACTIVE")  # ACTIVE, PARTIALLY_ACTIVE, INACTIVE, BLOCKED, TIMEOUT, UNKNOWN
    discovered_from: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), onupdate=func.now(), server_default=func.now())


class DnsRecord(Base):
    __tablename__ = "dns_records"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    asset_id: Mapped[str] = mapped_column(String, ForeignKey("assets.id", ondelete="cascade"), index=True, nullable=False)
    record_type: Mapped[str] = mapped_column(String, index=True, nullable=False)  # A, AAAA, CNAME, MX, NS, TXT, SOA
    value: Mapped[str] = mapped_column(Text, nullable=False)
    ttl: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class IpAddress(Base):
    __tablename__ = "ip_addresses"
    __table_args__ = (UniqueConstraint("asset_id", "ip", name="uq_ip_asset_ip"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    asset_id: Mapped[str] = mapped_column(String, ForeignKey("assets.id", ondelete="cascade"), index=True, nullable=False)
    ip: Mapped[str] = mapped_column(String, index=True, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=4)
    asn: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    org: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    country: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    reverse_dns: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ==========================================================================
# 6. Network Assessment (§15-18, §87)
# ==========================================================================
class Port(Base):
    __tablename__ = "ports"
    __table_args__ = (UniqueConstraint("asset_id", "port", "protocol", name="uq_port_asset_port_proto"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    asset_id: Mapped[str] = mapped_column(String, ForeignKey("assets.id", ondelete="cascade"), index=True, nullable=False)
    ip: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String, nullable=False, default="tcp")
    state: Mapped[str] = mapped_column(String, nullable=False, default="open")
    service: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    banner: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class Service(Base):
    __tablename__ = "services"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    asset_id: Mapped[str] = mapped_column(String, ForeignKey("assets.id", ondelete="cascade"), index=True, nullable=False)
    port_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("ports.id", ondelete="cascade"), nullable=True)
    name: Mapped[str] = mapped_column(String, index=True, nullable=False)  # http, https, ssh, rdp, mysql, redis, etc.
    product: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    version: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    cpe: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    protocol: Mapped[str] = mapped_column(String, nullable=False, default="tcp")
    tls_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    banner: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class TlsRecord(Base):
    __tablename__ = "tls_records"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    asset_id: Mapped[str] = mapped_column(String, ForeignKey("assets.id", ondelete="cascade"), index=True, nullable=False)
    version: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # TLSv1.2, TLSv1.3
    cipher_suite: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    cert_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    hostname_mismatch: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    hsts_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    weak_crypto_detected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    issuer: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    subject: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    not_before: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    not_after: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    san_dns: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Certificate(Base):
    __tablename__ = "certificates"
    __table_args__ = (UniqueConstraint("asset_id", "fingerprint_sha256", name="uq_cert_asset_fp"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    asset_id: Mapped[str] = mapped_column(String, ForeignKey("assets.id", ondelete="cascade"), index=True, nullable=False)
    hostname: Mapped[str] = mapped_column(String, index=True, nullable=False)
    fingerprint_sha256: Mapped[str] = mapped_column(String, index=True, nullable=False)
    subject_cn: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    issuer_cn: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    not_before: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    not_after: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    san_dns: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    signature_algorithm: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ==========================================================================
# 7. Web & Parameter Pipeline (§13, §68)
# ==========================================================================
class URL(Base):
    __tablename__ = "urls"
    __table_args__ = (UniqueConstraint("asset_id", "url", name="uq_url_asset_url"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    asset_id: Mapped[str] = mapped_column(String, ForeignKey("assets.id", ondelete="cascade"), index=True, nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    scheme: Mapped[str] = mapped_column(String, nullable=False)
    host: Mapped[str] = mapped_column(String, index=True, nullable=False)
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    query: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    content_type: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    title: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    redirect_chain: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    auth_context_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), onupdate=func.now(), server_default=func.now())


class Parameter(Base):
    __tablename__ = "parameters"
    __table_args__ = (UniqueConstraint("url_id", "name", "location", name="uq_param_url_name_loc"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    url_id: Mapped[str] = mapped_column(String, ForeignKey("urls.id", ondelete="cascade"), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    location: Mapped[str] = mapped_column(String, nullable=False)  # query, body, header, cookie, path
    type: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    source: Mapped[str] = mapped_column(String, nullable=False, default="crawler")
    observed_values_hash: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)


class Technology(Base):
    __tablename__ = "technologies"
    __table_args__ = (UniqueConstraint("asset_id", "name", "version", name="uq_tech_asset_name_version"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    asset_id: Mapped[str] = mapped_column(String, ForeignKey("assets.id", ondelete="cascade"), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    category: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    version: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    cpe: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


# ==========================================================================
# 8. Screenshots & Browser Intelligence (§10-12, §39)
# ==========================================================================
class Screenshot(Base):
    __tablename__ = "screenshots"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id", ondelete="cascade"), index=True, nullable=False)
    asset_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("assets.id", ondelete="cascade"), nullable=True)
    url_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("urls.id", ondelete="set null"), nullable=True)
    storage_path: Mapped[str] = mapped_column(Text, nullable=False)
    thumbnail_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    viewport: Mapped[str] = mapped_column(String, nullable=False, default="1280x720")
    status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    page_title: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    content_hash: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    visual_hash: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    trigger: Mapped[str] = mapped_column(String, nullable=False, default="homepage")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ==========================================================================
# 9. Intelligence: CVE / CPE / CWE & MITRE ATT&CK TTP (§23-26)
# ==========================================================================
class VulnerabilityCatalog(Base):
    __tablename__ = "vulnerability_catalog"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    cve_id: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    severity: Mapped[str] = mapped_column(String, nullable=False, default="MEDIUM")
    cwe_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    title: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[Text] = mapped_column(Text, nullable=False)
    affected_cpe_pattern: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    references_: Mapped[list] = mapped_column("references", JSON, nullable=False, default=list)
    published_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class TtpObservation(Base):
    __tablename__ = "ttp_observations"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id", ondelete="cascade"), index=True, nullable=False)
    asset_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("assets.id", ondelete="set null"), nullable=True)
    technique_id: Mapped[str] = mapped_column(String, index=True, nullable=False)
    technique_name: Mapped[str] = mapped_column(String, nullable=False)
    tactic: Mapped[str] = mapped_column(String, index=True, nullable=False)
    confidence: Mapped[str] = mapped_column(String, nullable=False, default="OBSERVED")
    evidence: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    mitre_url: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ==========================================================================
# 10. Validation Engine & Security Test Rules (§29, §92)
# ==========================================================================
class ValidationRule(Base):
    __tablename__ = "validation_rules"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    rule_id: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    rule_version: Mapped[str] = mapped_column(String, nullable=False, default="1.0.0")
    category: Mapped[str] = mapped_column(String, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String, nullable=False, default="MEDIUM")
    confidence_default: Mapped[str] = mapped_column(String, nullable=False, default="VALIDATED")
    mode: Mapped[str] = mapped_column(String, nullable=False, default="SAFE_ACTIVE")
    preconditions: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    test_definition: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), onupdate=func.now(), server_default=func.now())


class Validation(Base):
    __tablename__ = "validations"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id", ondelete="cascade"), index=True, nullable=False)
    asset_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("assets.id", ondelete="set null"), nullable=True)
    rule_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("validation_rules.id", ondelete="set null"), nullable=True)
    status: Mapped[str] = mapped_column(String, index=True, nullable=False, default="QUEUED")
    confidence: Mapped[str] = mapped_column(String, nullable=False, default="OBSERVED")
    input_data: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    result_data: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


# ==========================================================================
# 11. Evidence Engine & PoC Management (V8 §25-§28)
# ==========================================================================
class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id", ondelete="cascade"), index=True, nullable=False)
    asset_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("assets.id", ondelete="set null"), nullable=True)
    validation_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("validations.id", ondelete="set null"), nullable=True)
    evidence_type: Mapped[str] = mapped_column(String, index=True, nullable=False)
    source: Mapped[str] = mapped_column(String, nullable=False, default="DIRECT_OBSERVATION")
    request_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    response_hash: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    sha256_hash: Mapped[Optional[str]] = mapped_column(String, index=True, nullable=True)
    collector_version: Mapped[Optional[str]] = mapped_column(String, nullable=True, default="v8.0.0")
    campaign_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    evidence_type_v5: Mapped[Optional[str]] = mapped_column(String, nullable=True, default="observation")
    data: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    storage_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    provenance: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    confidence: Mapped[str] = mapped_column(String, nullable=False, default="DIRECT_OBSERVATION")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class EvidencePackage(Base):
    """Structured Evidence Package per finding (V8 §28)."""
    __tablename__ = "evidence_packages"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    finding_id: Mapped[str] = mapped_column(String, ForeignKey("findings.id", ondelete="cascade"), index=True, nullable=False)
    summary_data: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    timeline_data: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    request_metadata: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    response_metadata: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    validation_data: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    reproduction_md: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    hashes_data: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ProofProfile(Base):
    """Proof-of-Impact Profile per vulnerability type (V8 §25)."""
    __tablename__ = "proof_profiles"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    vulnerability_type: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    objective: Mapped[str] = mapped_column(Text, nullable=False)
    prerequisites: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    safe_validation: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    controlled_validation: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    impact_signal: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    evidence_required: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    stop_conditions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    cleanup_actions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class PoC(Base):
    __tablename__ = "pocs"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    finding_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("findings.id", ondelete="cascade"), index=True, nullable=True)
    title: Mapped[str] = mapped_column(String, nullable=False)
    preconditions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    target: Mapped[str] = mapped_column(Text, nullable=False)
    request_payload: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    expected_result: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    actual_result: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    reproduction_steps: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    safety_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_sanitized: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ==========================================================================
# 12. Finding Management & Lifecycle (V8 §20, §21, §26, §27, §36)
# ==========================================================================
class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("scan_id", "asset_id", "finding_type", "title", name="uq_finding_scan_asset_type_title"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    finding_code: Mapped[Optional[str]] = mapped_column(String, index=True, nullable=True)  # e.g., BH-2026-001
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id", ondelete="cascade"), index=True, nullable=False)
    domain_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("domains.id", ondelete="set null"), nullable=True)
    asset_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("assets.id", ondelete="set null"), nullable=True)
    url_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("urls.id", ondelete="set null"), nullable=True)
    finding_type: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, index=True, nullable=False, default="INFO")  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence: Mapped[str] = mapped_column(String, nullable=False, default="CONFIRMED")  # OBSERVED, SUSPECTED, VALIDATED, CONFIRMED
    evidence_level: Mapped[str] = mapped_column(String, index=True, nullable=False, default="E0")  # E0, E1, E2, E3, E4 (V8 §26)
    evidence_score: Mapped[int] = mapped_column(Integer, nullable=False, default=10)  # 0-100 (V8 §27)
    exploitability_state: Mapped[str] = mapped_column(String, index=True, nullable=False, default="CANDIDATE")  # NOT_MATCHED, CANDIDATE, APPLICABLE, VALIDATION_PENDING, VALIDATED, CONFIRMED, NOT_EXPLOITABLE, PATCHED, INCONCLUSIVE (V8 §21)
    priority: Mapped[str] = mapped_column(String, index=True, nullable=False, default="P2")  # P0, P1, P2, P3, P4 (V8 §36)
    rule_version: Mapped[Optional[str]] = mapped_column(String, nullable=True, default="v8.0.0")
    impact_matrix: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    validation_status: Mapped[str] = mapped_column(String, index=True, nullable=False, default="DISCOVERED")
    root_cause: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    preconditions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    expected_result: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    actual_result: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    executive_explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    business_impact: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cwe_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    cve_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    status: Mapped[str] = mapped_column(String, index=True, nullable=False, default="OPEN")
    dedup_key: Mapped[Optional[str]] = mapped_column(String, index=True, nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    impact: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    technical_details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    reproducibility_meta: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), onupdate=func.now(), server_default=func.now())


class FindingReference(Base):
    __tablename__ = "finding_references"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    finding_id: Mapped[str] = mapped_column(String, ForeignKey("findings.id", ondelete="cascade"), index=True, nullable=False)
    ref_type: Mapped[str] = mapped_column(String, nullable=False, default="cve")
    url: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[Optional[str]] = mapped_column(String, nullable=True)


# ==========================================================================
# 13. Retesting Engine (V8 §37, §42)
# ==========================================================================
class Retest(Base):
    __tablename__ = "retests"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id", ondelete="cascade"), index=True, nullable=False)
    finding_id: Mapped[str] = mapped_column(String, ForeignKey("findings.id", ondelete="cascade"), index=True, nullable=False)
    operator_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    status: Mapped[str] = mapped_column(String, index=True, nullable=False, default="PENDING")  # PENDING, RUNNING, PASSED (FIXED), FAILED (REOPENED), INCONCLUSIVE
    before_evidence_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("evidence.id", ondelete="set null"), nullable=True)
    after_evidence_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("evidence.id", ondelete="set null"), nullable=True)
    comparison_result: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


# ==========================================================================
# 14. Report Engine (V8 §37-§39)
# ==========================================================================
class Report(Base):
    __tablename__ = "reports"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id", ondelete="cascade"), index=True, nullable=False)
    domain_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("domains.id", ondelete="set null"), nullable=True)
    title: Mapped[str] = mapped_column(String, nullable=False)
    report_type: Mapped[str] = mapped_column(String, nullable=False, default="executive")  # executive, technical, bug_bounty, cve_dossier, finding, retest, evidence_package
    report_format: Mapped[str] = mapped_column(String, nullable=False, default="markdown")  # markdown, html, pdf, json
    view_perspective: Mapped[str] = mapped_column(String, nullable=False, default="customer")  # researcher, customer
    executive_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    stats_summary: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    storage_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_redacted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ==========================================================================
# 15. Observability, Events & Audit Trail (V8 §49)
# ==========================================================================
class ScanEvent(Base):
    __tablename__ = "scan_events"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id", ondelete="cascade"), index=True, nullable=False)
    asset_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("assets.id", ondelete="set null"), nullable=True)
    event_type: Mapped[str] = mapped_column(String, index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False, default="info")
    message: Mapped[str] = mapped_column(Text, nullable=False)
    data: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id", ondelete="cascade"), index=True, nullable=False)
    actor: Mapped[str] = mapped_column(String, nullable=False, default="system")
    action: Mapped[str] = mapped_column(String, nullable=False)
    target: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    scope: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    authorization_ref: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    tool_name: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    tool_version: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    ai_decision_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    result_status: Mapped[str] = mapped_column(String, nullable=False, default="SUCCESS")
    evidence_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    details: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Observation(Base):
    __tablename__ = "observations"
    __table_args__ = (UniqueConstraint("scan_id", "asset_id", "observation_type", "title", name="uq_observation"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id", ondelete="cascade"), index=True, nullable=False)
    asset_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("assets.id", ondelete="set null"), nullable=True)
    observation_type: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    evidence: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ==========================================================================
# 16. V8 Capability Registry & Policies (V8 §4, §48)
# ==========================================================================
class Capability(Base):
    """Capability Registry entity defining risk levels and gating (V8 §4)."""
    __tablename__ = "capabilities"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    name: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    category: Mapped[str] = mapped_column(String, index=True, nullable=False)
    risk_level: Mapped[str] = mapped_column(String, nullable=False, default="L2_SAFE_ACTIVE")  # L0_OBSERVE, L1_PASSIVE, L2_SAFE_ACTIVE, L3_CONTROLLED, L4_HIGH_RISK
    required_authorization: Mapped[str] = mapped_column(String, nullable=False, default="STANDARD_SCOPE")
    supported_targets: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    dependencies: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    safe_mode: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    lab_mode: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    production_mode: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    evidence_requirements: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    cleanup_requirements: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class CapabilityPolicy(Base):
    """Policies governing capability execution per profile (V8 §4, §48)."""
    __tablename__ = "capability_policies"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    capability_id: Mapped[str] = mapped_column(String, ForeignKey("capabilities.id", ondelete="cascade"), index=True, nullable=False)
    profile: Mapped[str] = mapped_column(String, index=True, nullable=False)  # bug_hunt, deep_bug_hunt, pentest, adversary_simulation
    allowed_actions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    requires_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    lab_only: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    rate_limit_override: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ==========================================================================
# 17. V8 Gated Approvals (V8 §3, §48)
# ==========================================================================
class Approval(Base):
    """Operator approval gate for high-risk (L3/L4) simulation actions (V8 §3)."""
    __tablename__ = "approvals"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id", ondelete="cascade"), index=True, nullable=False)
    action: Mapped[str] = mapped_column(String, nullable=False)
    module: Mapped[str] = mapped_column(String, nullable=False)
    target: Mapped[str] = mapped_column(String, nullable=False)
    risk_level: Mapped[str] = mapped_column(String, nullable=False, default="L3_CONTROLLED")
    status: Mapped[str] = mapped_column(String, index=True, nullable=False, default="PENDING")  # PENDING, APPROVED, REJECTED, EXPIRED, CANCELLED
    requester_id: Mapped[str] = mapped_column(String, nullable=False, default="system")
    approver_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    rollback_plan: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    hard_time_limit_sec: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    audit_trail_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    decided_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


# ==========================================================================
# 18. V8 Local AI Subsystem (V8 §9-§12, §48)
# ==========================================================================
class AiRun(Base):
    """AI agent reasoning or triage execution instance (V8 §9)."""
    __tablename__ = "ai_runs"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id", ondelete="cascade"), index=True, nullable=False)
    agent_role: Mapped[str] = mapped_column(String, index=True, nullable=False)  # recon, vuln_analyst, validation_planner, evidence_critic, report_agent, retest_agent
    model_name: Mapped[str] = mapped_column(String, nullable=False, default="local-embedded")
    prompt_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    input_data: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    output_data: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    status: Mapped[str] = mapped_column(String, nullable=False, default="COMPLETED")  # RUNNING, COMPLETED, FAILED
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class AiDecision(Base):
    """AI structured action proposal and policy decision audit record (V8 §11)."""
    __tablename__ = "ai_decisions"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    ai_run_id: Mapped[str] = mapped_column(String, ForeignKey("ai_runs.id", ondelete="cascade"), index=True, nullable=False)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id", ondelete="cascade"), index=True, nullable=False)
    decision_type: Mapped[str] = mapped_column(String, nullable=False)  # action_proposal, test_plan, quality_gate, triage
    proposed_action: Mapped[str] = mapped_column(String, nullable=False)
    proposed_module: Mapped[str] = mapped_column(String, nullable=False)
    proposed_target: Mapped[str] = mapped_column(String, nullable=False)
    risk_level: Mapped[str] = mapped_column(String, nullable=False, default="L2_SAFE_ACTIVE")
    policy_verdict: Mapped[str] = mapped_column(String, nullable=False, default="ALLOW")  # ALLOW, DENY, REQUIRES_APPROVAL
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AiToolCall(Base):
    """Audited AI tool execution trace (V8 §9, §48)."""
    __tablename__ = "ai_tool_calls"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    ai_run_id: Mapped[str] = mapped_column(String, ForeignKey("ai_runs.id", ondelete="cascade"), index=True, nullable=False)
    tool_name: Mapped[str] = mapped_column(String, nullable=False)
    arguments: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    result: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    policy_checked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ==========================================================================
# 19. V8 Hypothesis Engine (V8 §35, §48)
# ==========================================================================
class Hypothesis(Base):
    """Analyst & AI security hypothesis tracking (V8 §35)."""
    __tablename__ = "hypotheses"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id", ondelete="cascade"), index=True, nullable=False)
    asset_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("assets.id", ondelete="set null"), nullable=True)
    title: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    state: Mapped[str] = mapped_column(String, index=True, nullable=False, default="IDEA")  # IDEA, TESTING, SUPPORTED, CONFIRMED, REJECTED
    relevant_assets: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    existing_evidence: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    preconditions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    safe_test_sequence: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    expected_outcomes: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    rejection_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), onupdate=func.now(), server_default=func.now())


# ==========================================================================
# 20. V8 Attack Path & Graph Engine (V8 §18, §19, §48)
# ==========================================================================
class AttackPath(Base):
    """Graph-based Attack Path representation (V8 §19)."""
    __tablename__ = "attack_paths"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id", ondelete="cascade"), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    start_node: Mapped[str] = mapped_column(String, nullable=False)
    target_node: Mapped[str] = mapped_column(String, nullable=False)
    overall_risk: Mapped[str] = mapped_column(String, nullable=False, default="MEDIUM")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.8)
    is_validated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    graph_data: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AttackPathEdge(Base):
    """Individual edge in the Attack Path Graph (V8 §19)."""
    __tablename__ = "attack_path_edges"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    attack_path_id: Mapped[str] = mapped_column(String, ForeignKey("attack_paths.id", ondelete="cascade"), index=True, nullable=False)
    source_node_type: Mapped[str] = mapped_column(String, nullable=False)  # Asset, Identity, Credential, Service, Vulnerability, Finding
    source_node_id: Mapped[str] = mapped_column(String, nullable=False)
    target_node_type: Mapped[str] = mapped_column(String, nullable=False)
    target_node_id: Mapped[str] = mapped_column(String, nullable=False)
    edge_type: Mapped[str] = mapped_column(String, index=True, nullable=False)  # REACHABLE, AUTHENTICATES, ACCESSES, TRUSTS, DEPENDS_ON, POTENTIALLY_ESCALATES_TO
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    evidence_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    source: Mapped[str] = mapped_column(String, nullable=False, default="DIRECT_OBSERVATION")
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ==========================================================================
# 21. V8 Credential & Hash Assessment Subsystem (V8 §13, §48)
# ==========================================================================
class CredentialArtifact(Base):
    """Discovered or extracted credential/hash material (V8 §13)."""
    __tablename__ = "credential_artifacts"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id", ondelete="cascade"), index=True, nullable=False)
    asset_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("assets.id", ondelete="set null"), nullable=True)
    raw_identifier: Mapped[str] = mapped_column(String, nullable=False)  # Redacted identifier
    credential_type: Mapped[str] = mapped_column(String, nullable=False)  # hash, plaintext_token, password, key, api_secret
    hash_algorithm: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    salt_present: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    work_factor: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    entropy: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    weak_pattern_detected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    password_policy_weakness: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    state: Mapped[str] = mapped_column(String, index=True, nullable=False, default="DISCOVERED")  # DISCOVERED, CLASSIFIED, OFFLINE_ANALYSIS, REQUIRES_AUTHORIZATION, VALIDATED, REVOKED
    authorized_accounts_only: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class CredentialContext(Base):
    """Scoped credential context for authorized target verification (V8 §13, §14)."""
    __tablename__ = "credential_contexts"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id", ondelete="cascade"), index=True, nullable=False)
    identity_name: Mapped[str] = mapped_column(String, nullable=False)
    role: Mapped[str] = mapped_column(String, nullable=False, default="test_user")
    allowed_targets: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    is_disposable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ==========================================================================
# 22. V8 Validation & Proof Profiles (V8 §22, §23, §48)
# ==========================================================================
class ValidationProfile(Base):
    """Technology-specific validation profile (V8 §22, §23)."""
    __tablename__ = "validation_profiles"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    name: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    target_type: Mapped[str] = mapped_column(String, index=True, nullable=False)  # service, webapp
    fingerprint_pattern: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    safe_checks: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    configuration_checks: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    cve_correlation_rules: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    validation_rules: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    evidence_requirements: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ==========================================================================
# 23. V8 Cleanup Manager (V8 §44, §48)
# ==========================================================================
class CleanupTask(Base):
    """Automated resource cleanup tracking (V8 §44)."""
    __tablename__ = "cleanup_tasks"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id", ondelete="cascade"), index=True, nullable=False)
    resource_type: Mapped[str] = mapped_column(String, nullable=False)  # canary, test_account, temporary_artifact, session, lab_container
    resource_identifier: Mapped[str] = mapped_column(String, nullable=False)
    cleanup_action: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, index=True, nullable=False, default="PENDING")  # PENDING, RUNNING, COMPLETED, FAILED, MANUAL_REQUIRED
    deadline: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    result_details: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


# ==========================================================================
# 24. V8 Disposable Lab Environments (V8 §45, §48)
# ==========================================================================
class LabEnvironment(Base):
    """Lab environment for isolated high-risk adversary simulation (V8 §45)."""
    __tablename__ = "lab_environments"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    name: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_disposable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    network_bridge: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    configs: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class LabTarget(Base):
    """Individual target container/fixture within a lab environment (V8 §45)."""
    __tablename__ = "lab_targets"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    lab_id: Mapped[str] = mapped_column(String, ForeignKey("lab_environments.id", ondelete="cascade"), index=True, nullable=False)
    target_name: Mapped[str] = mapped_column(String, nullable=False)
    service_type: Mapped[str] = mapped_column(String, nullable=False)
    ip_address: Mapped[str] = mapped_column(String, nullable=False)
    ports: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    vulnerability_profile: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ==========================================================================
# 25. V8 Evidence Scores & Requirements (V8 §26, §27, §48)
# ==========================================================================
class EvidenceScore(Base):
    """Structured quality scores assessed by the Evidence Critic (V8 §26, §27, §29)."""
    __tablename__ = "evidence_scores"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    finding_id: Mapped[str] = mapped_column(String, ForeignKey("findings.id", ondelete="cascade"), index=True, nullable=False)
    reproducibility_score: Mapped[int] = mapped_column(Integer, nullable=False, default=100)  # 0-100
    impact_proof_score: Mapped[int] = mapped_column(Integer, nullable=False, default=100)  # 0-100
    artifact_completeness_score: Mapped[int] = mapped_column(Integer, nullable=False, default=100)  # 0-100
    timeline_integrity_score: Mapped[int] = mapped_column(Integer, nullable=False, default=100)  # 0-100
    cryptographic_score: Mapped[int] = mapped_column(Integer, nullable=False, default=100)  # 0-100
    overall_score: Mapped[int] = mapped_column(Integer, nullable=False, default=100)  # 0-100
    critic_notes: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class EvidenceRequirement(Base):
    """Standardized evidence requirements per vulnerability class (V8 §25, §27)."""
    __tablename__ = "evidence_requirements"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    vulnerability_type: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    minimum_evidence_level: Mapped[str] = mapped_column(String, nullable=False, default="E2")  # E0, E1, E2, E3, E4
    required_artifacts: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    canary_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    screenshot_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    request_response_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ==========================================================================
# 26. V9 Campaign Management Subsystem
# ==========================================================================
class Campaign(Base):
    """Orchestrated Assessment Campaign holding multiple scan sessions and targets."""
    __tablename__ = "campaigns"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    name: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    scope_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("scopes.id", ondelete="set null"), nullable=True)
    objectives: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    rules_of_engagement: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String, index=True, nullable=False, default="ACTIVE")  # ACTIVE, PAUSED, COMPLETED, ARCHIVED
    target_domains: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    created_by: Mapped[Optional[str]] = mapped_column(String, ForeignKey("users.id", ondelete="set null"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


# ==========================================================================
# 27. V9 Artifact Intelligence Subsystem
# ==========================================================================
class Artifact(Base):
    """Captured or discovered binary/text artifact (SQL dumps, CSVs, logs, configs)."""
    __tablename__ = "artifacts"
    __table_args__ = (UniqueConstraint("scan_id", "sha256_hash", name="uq_artifact_scan_sha256"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id", ondelete="cascade"), index=True, nullable=False)
    asset_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("assets.id", ondelete="set null"), nullable=True)
    url_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("urls.id", ondelete="set null"), nullable=True)
    finding_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("findings.id", ondelete="set null"), nullable=True)
    filename: Mapped[str] = mapped_column(String, nullable=False)
    file_type: Mapped[str] = mapped_column(String, index=True, nullable=False)  # sql_dump, csv_export, log_file, env_file, git_config, backup_archive
    mime_type: Mapped[str] = mapped_column(String, nullable=False, default="application/octet-stream")
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    sha256_hash: Mapped[str] = mapped_column(String, index=True, nullable=False)
    storage_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    quarantine_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    state: Mapped[str] = mapped_column(String, index=True, nullable=False, default="DISCOVERED")  # DISCOVERED, CLASSIFIED, ACQUISITION_PENDING, QUARANTINED, PARSED, INTELLIGENCE_EXTRACTED, CORRELATED, EVIDENCE_READY
    schema_data: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)  # Database name, tables, columns, indexes, types
    extracted_entities: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)  # Users, password hashes, tokens, API keys, PII fields
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), onupdate=func.now(), server_default=func.now())


# ==========================================================================
# 28. V9 Identity & Authorization Subsystem
# ==========================================================================
class Identity(Base):
    """Extracted IAM user, account, role, or principal for privilege matrix validation."""
    __tablename__ = "identities"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id", ondelete="cascade"), index=True, nullable=False)
    asset_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("assets.id", ondelete="set null"), nullable=True)
    username: Mapped[str] = mapped_column(String, index=True, nullable=False)
    email: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    role: Mapped[str] = mapped_column(String, nullable=False, default="user")
    privileges: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    source_artifact_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("artifacts.id", ondelete="set null"), nullable=True)
    source_type: Mapped[str] = mapped_column(String, nullable=False, default="artifact")  # sql_dump, csv_export, jwt, api
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ==========================================================================
# 29. V9 Test Plan & Step-by-Step Validation Machine
# ==========================================================================
class TestPlan(Base):
    """Structured security test plan with pre-checks, baselines, and comparison phases."""
    __tablename__ = "test_plans"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id", ondelete="cascade"), index=True, nullable=False)
    asset_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("assets.id", ondelete="set null"), nullable=True)
    target_url: Mapped[str] = mapped_column(Text, nullable=False)
    vulnerability_type: Mapped[str] = mapped_column(String, index=True, nullable=False)
    priority: Mapped[str] = mapped_column(String, nullable=False, default="P2")
    state: Mapped[str] = mapped_column(String, index=True, nullable=False, default="NOT_STARTED")  # NOT_STARTED, PRECHECK, BASELINE, TESTING, COMPARISON, EVIDENCE, IMPACT, RESULT
    preconditions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    test_payloads: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    baseline_response: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    test_results: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), onupdate=func.now(), server_default=func.now())


class PreconditionCheck(Base):
    """Audited pre-condition execution item before active security validation."""
    __tablename__ = "precondition_checks"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    test_plan_id: Mapped[str] = mapped_column(String, ForeignKey("test_plans.id", ondelete="cascade"), index=True, nullable=False)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id", ondelete="cascade"), index=True, nullable=False)
    check_name: Mapped[str] = mapped_column(String, nullable=False)
    target: Mapped[str] = mapped_column(Text, nullable=False)
    passed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    evidence_data: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# Backward-compatibility aliases for legacy callers
Event = ScanEvent
AttackChain = AttackPath

__all__ = [
    "User", "ScopeModel", "Domain", "Scan", "DeviceTrial", "Asset", "DnsRecord", "IpAddress",
    "Port", "Service", "TlsRecord", "Certificate", "URL", "Parameter", "Technology", "Screenshot",
    "VulnerabilityCatalog", "TtpObservation", "ValidationRule", "Validation", "Evidence", "EvidencePackage",
    "ProofProfile", "PoC", "Finding", "FindingReference", "Retest", "Report", "ScanEvent", "Event", "AuditLog", "Observation",
    "Capability", "CapabilityPolicy", "Approval", "AiRun", "AiDecision", "AiToolCall", "Hypothesis",
    "AttackPath", "AttackChain", "AttackPathEdge", "CredentialArtifact", "CredentialContext", "ValidationProfile",
    "CleanupTask", "LabEnvironment", "LabTarget", "EvidenceScore", "EvidenceRequirement",
    "Campaign", "Artifact", "Identity", "TestPlan", "PreconditionCheck",
]
