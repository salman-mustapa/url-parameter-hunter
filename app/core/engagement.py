"""Explicit program boundaries and reusable, tenant-neutral report identity."""
from __future__ import annotations

import base64
import io
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.scope_engine import is_valid_hostname


class ReportProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    organization: str = Field(default="", max_length=160)
    program: str = Field(default="", max_length=160)
    assessor: str = Field(default="", max_length=120)
    asset_name: str = Field(default="", max_length=160)
    asset_type: Literal["Web / API", "Web", "API", "Server", "Other"] = "Web / API"
    application_version: str = Field(default="", max_length=100)
    contact: str = Field(default="", max_length=180)
    classification: Literal["CONFIDENTIAL", "INTERNAL", "RESTRICTED"] = "CONFIDENTIAL"
    executive_context: str = Field(default="", max_length=3000)
    logo_data_url: str = Field(default="", max_length=360000)

    @field_validator("logo_data_url")
    @classmethod
    def safe_logo(cls, value):
        if not value:
            return ""
        # No remote fetch, SVG, filesystem path or active content in exported reports.
        if not value.startswith(("data:image/png;base64,", "data:image/jpeg;base64,")):
            raise ValueError("Logo must be a PNG/JPEG upload, not a remote URL")
        try:
            from PIL import Image
            raw = base64.b64decode(value.split(",", 1)[1], validate=True)
            if len(raw) > 256 * 1024:
                raise ValueError("Logo exceeds 256 KiB")
            with Image.open(io.BytesIO(raw)) as source:
                if source.width * source.height > 4_000_000 or source.format not in {"PNG", "JPEG"}:
                    raise ValueError("Unsupported logo dimensions or format")
                source.thumbnail((512, 256))
                cleaned = source.convert("RGBA")
                output = io.BytesIO()
                cleaned.save(output, format="PNG")
            return "data:image/png;base64," + base64.b64encode(output.getvalue()).decode("ascii")
        except Exception as error:
            raise ValueError("Invalid logo: use a PNG/JPEG up to 256 KiB and 4 megapixels") from error


class EngagementRules(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    authorization_reference: str = Field(min_length=3, max_length=300)
    authorization_acknowledged: bool = False
    starts_at: datetime | None = None
    ends_at: datetime | None = None
    scope_hosts: list[str] = Field(default_factory=list, max_length=100)
    excluded_hosts: list[str] = Field(default_factory=list, max_length=100)
    allowed_ports: list[int] = Field(default_factory=lambda: [80, 443], min_length=1, max_length=100)
    max_rps: int = Field(default=5, ge=1, le=30)
    notes: str = Field(default="", max_length=3000)
    report: ReportProfile = Field(default_factory=ReportProfile)

    @field_validator("starts_at", "ends_at")
    @classmethod
    def aware_time(cls, value):
        if value is not None and value.utcoffset() is None:
            raise ValueError("Testing times must include a timezone")
        return value

    @field_validator("scope_hosts", "excluded_hosts")
    @classmethod
    def hosts(cls, values):
        result = []
        for value in values:
            value = value.lower().strip().rstrip(".")
            hostname = value[2:] if value.startswith("*.") else value
            if not is_valid_hostname(hostname):
                raise ValueError("Scope entries must be exact hosts or *.domain patterns, not URLs")
            if value not in result:
                result.append(value)
        return result

    @field_validator("allowed_ports")
    @classmethod
    def ports(cls, values):
        if any(port < 1 or port > 65535 for port in values):
            raise ValueError("Allowed ports must be between 1 and 65535")
        return sorted(set(values))

    @model_validator(mode="after")
    def validate_rules(self):
        if not self.authorization_acknowledged:
            raise ValueError("Confirm that the target owner authorized this engagement")
        if self.starts_at and self.ends_at and self.ends_at <= self.starts_at:
            raise ValueError("Testing end must be after testing start")
        return self

    def assert_active(self):
        now = datetime.now(timezone.utc)
        if self.starts_at and now < self.starts_at:
            raise ValueError("Testing window has not started")
        if self.ends_at and now >= self.ends_at:
            raise ValueError("Testing window has expired; obtain renewed authorization")


def report_context(scan) -> dict:
    options = scan.options or {}
    engagement = dict(options.get("engagement") or {})
    return {
        "report": options.get("report_profile") or engagement.pop("report", {}) or {},
        "rules": {k: v for k, v in engagement.items() if k != "report"},
        "authorization_reference": scan.authorization_reference or None,
        "profile": scan.profile, "validation_level": scan.validation_level,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "scope_note": "Recorded rules are not independent proof of authorization or complete test coverage.",
        "prohibited": ["DoS / resource exhaustion", "Brute force / credential stuffing", "Social engineering / phishing",
                       "Unapproved access changes, data extraction or lateral movement"],
    }
