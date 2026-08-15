from sqlalchemy import Column, String, DateTime, ForeignKey, Integer, Text, Boolean, JSON, Float
from sqlalchemy.sql import func
import uuid
from app.services.database import Base

def gen_uuid() -> str:
    return str(uuid.uuid4())

class Scan(Base):
    __tablename__ = "scans"
    id = Column(String, primary_key=True, default=gen_uuid)
    root_domain = Column(String, index=True, nullable=False)
    status = Column(String, index=True, nullable=False, default="created")
    profile = Column(String, nullable=False, default="standard")
    options = Column(JSON, nullable=False, default=dict)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    progress = Column(JSON, nullable=False, default=dict)

class Asset(Base):
    __tablename__ = "assets"
    id = Column(String, primary_key=True, default=gen_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="cascade"), index=True, nullable=False)
    parent_id = Column(String, ForeignKey("assets.id", ondelete="set null"), nullable=True)
    asset_type = Column(String, index=True, nullable=False)
    hostname = Column(String, index=True, nullable=True)
    fqdn = Column(String, index=True, nullable=True)
    ip = Column(String, index=True, nullable=True)
    depth = Column(Integer, nullable=False, default=0)
    status = Column(String, nullable=False, default="discovered")
    discovered_from = Column(JSON, nullable=False, default=list)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), onupdate=func.now(), server_default=func.now())
    metadata_ = Column("metadata", JSON, nullable=False, default=dict)

class Port(Base):
    __tablename__ = "ports"
    id = Column(String, primary_key=True, default=gen_uuid)
    asset_id = Column(String, ForeignKey("assets.id", ondelete="cascade"), index=True, nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String, nullable=False, default="tcp")
    state = Column(String, nullable=False, default="open")
    service = Column(String, nullable=True)
    banner = Column(Text, nullable=True)

class URL(Base):
    __tablename__ = "urls"
    id = Column(String, primary_key=True, default=gen_uuid)
    asset_id = Column(String, ForeignKey("assets.id", ondelete="cascade"), index=True, nullable=False)
    url = Column(Text, nullable=False)
    scheme = Column(String, nullable=False)
    host = Column(String, index=True, nullable=False)
    port = Column(Integer, nullable=True)
    path = Column(Text, nullable=True)
    status_code = Column(Integer, nullable=True)
    content_type = Column(String, nullable=True)
    title = Column(String, nullable=True)

class Parameter(Base):
    __tablename__ = "parameters"
    id = Column(String, primary_key=True, default=gen_uuid)
    url_id = Column(String, ForeignKey("urls.id", ondelete="cascade"), index=True, nullable=False)
    name = Column(String, nullable=False)
    location = Column(String, nullable=False)
    type = Column(String, nullable=True)
    confidence = Column(Float, nullable=False, default=0.0)

class Technology(Base):
    __tablename__ = "technologies"
    id = Column(String, primary_key=True, default=gen_uuid)
    asset_id = Column(String, ForeignKey("assets.id", ondelete="cascade"), index=True, nullable=False)
    name = Column(String, nullable=False)
    version = Column(String, nullable=True)
    confidence = Column(Float, nullable=False, default=0.0)
    evidence = Column(Text, nullable=True)

class Finding(Base):
    __tablename__ = "findings"
    id = Column(String, primary_key=True, default=gen_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="cascade"), index=True, nullable=False)
    asset_id = Column(String, ForeignKey("assets.id", ondelete="set null"), nullable=True)
    finding_type = Column(String, nullable=False)
    title = Column(String, nullable=False)
    severity = Column(String, index=True, nullable=False, default="INFO")
    confidence = Column(Float, nullable=False, default=0.0)
    description = Column(Text, nullable=True)
    evidence = Column(JSON, nullable=False, default=dict)
    status = Column(String, index=True, nullable=False, default="open")
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), onupdate=func.now(), server_default=func.now())

class ScanEvent(Base):
    __tablename__ = "scan_events"
    id = Column(String, primary_key=True, default=gen_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="cascade"), index=True, nullable=False)
    asset_id = Column(String, ForeignKey("assets.id", ondelete="set null"), nullable=True)
    event_type = Column(String, index=True, nullable=False)
    severity = Column(String, nullable=False, default="info")
    message = Column(Text, nullable=False)
    data = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
