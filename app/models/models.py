from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Float, ForeignKey, Integer, JSON, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


def gen_uuid() -> str:
    return str(uuid.uuid4())


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    root_domain: Mapped[str] = mapped_column(String, index=True, nullable=False)
    status: Mapped[str] = mapped_column(String, index=True, nullable=False, default="created")
    profile: Mapped[str] = mapped_column(String, nullable=False, default="standard")
    options: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    progress: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("scan_id", "asset_type", "fingerprint", name="uq_asset_scan_type_fp"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id", ondelete="cascade"), index=True, nullable=False)
    parent_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("assets.id", ondelete="set null"), nullable=True)
    asset_type: Mapped[str] = mapped_column(String, index=True, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String, index=True, nullable=False)
    hostname: Mapped[Optional[str]] = mapped_column(String, index=True, nullable=True)
    fqdn: Mapped[Optional[str]] = mapped_column(String, index=True, nullable=True)
    ip: Mapped[Optional[str]] = mapped_column(String, index=True, nullable=True)
    depth: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String, nullable=False, default="discovered")
    discovered_from: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), onupdate=func.now(), server_default=func.now())


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
    status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    content_type: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    title: Mapped[Optional[str]] = mapped_column(String, nullable=True)


class Parameter(Base):
    __tablename__ = "parameters"
    __table_args__ = (UniqueConstraint("url_id", "name", "location", name="uq_param_url_name_loc"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    url_id: Mapped[str] = mapped_column(String, ForeignKey("urls.id", ondelete="cascade"), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    location: Mapped[str] = mapped_column(String, nullable=False)
    type: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)


class Technology(Base):
    __tablename__ = "technologies"
    __table_args__ = (UniqueConstraint("asset_id", "name", "version", name="uq_tech_asset_name_version"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    asset_id: Mapped[str] = mapped_column(String, ForeignKey("assets.id", ondelete="cascade"), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    version: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("scan_id", "asset_id", "finding_type", "title", name="uq_finding_scan_asset_type_title"),)
    id: Mapped[str] = mapped_column(String, primary_key=True, default=gen_uuid)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id", ondelete="cascade"), index=True, nullable=False)
    asset_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("assets.id", ondelete="set null"), nullable=True)
    finding_type: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, index=True, nullable=False, default="INFO")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String, index=True, nullable=False, default="OPEN")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), onupdate=func.now(), server_default=func.now())


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


__all__ = [
    "Scan", "Asset", "Port", "URL", "Parameter", "Technology", "Finding", "ScanEvent", "AuditLog", "Observation",
]
