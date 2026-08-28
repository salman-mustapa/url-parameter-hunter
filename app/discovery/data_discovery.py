"""Classify authorized application data without promoting exposure into exploitation."""

import re
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlsplit

from app.validation.context import ValidationContext
from app.validation.evidence.typed_evidence import Evidence, EvidenceType


class DataClassification(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    SENSITIVE = "SENSITIVE"
    HIGHLY_SENSITIVE = "HIGHLY_SENSITIVE"
    CREDENTIAL_MATERIAL = "CREDENTIAL_MATERIAL"


@dataclass(frozen=True)
class DiscoveredData:
    category: str
    classification: DataClassification
    evidence_id: str
    source_evidence_id: str
    field_path: str

    def to_dict(self):
        return dict(self.__dict__)


class DataDiscovery:
    _fields = {
        "email": ("emails", DataClassification.SENSITIVE),
        "username": ("usernames", DataClassification.INTERNAL),
        "id": ("identifiers", DataClassification.INTERNAL),
        "document": ("documents", DataClassification.SENSITIVE),
        "configuration": ("configuration", DataClassification.INTERNAL),
        "openapi": ("api_documentation", DataClassification.PUBLIC),
        "swagger": ("api_documentation", DataClassification.PUBLIC),
        "sources": ("source_maps", DataClassification.INTERNAL),
        "debug": ("debug_information", DataClassification.INTERNAL),
        "backup": ("backup_files", DataClassification.HIGHLY_SENSITIVE),
        "metadata": ("metadata", DataClassification.INTERNAL),
        "password": ("credentials", DataClassification.CREDENTIAL_MATERIAL),
        "api_key": ("credentials", DataClassification.CREDENTIAL_MATERIAL),
        "token": ("credentials", DataClassification.CREDENTIAL_MATERIAL),
    }

    def discover(self, context: ValidationContext, phase="discovery") -> list[DiscoveredData]:
        if not context._authorized:
            raise ValueError("Data discovery requires authorized collected evidence")
        (exchange,) = context.require(phase)
        found = []

        def add(category, classification, path, value):
            if len(found) >= 50:
                return
            item = Evidence(
                EvidenceType.CONFIGURATION,
                f"Observed {category}",
                f"{category} observed in captured application response; access policy not yet validated",
                data={
                    "classification": classification.value,
                    "category": category,
                    "field_path": path,
                    "sample": {path.rsplit(".", 1)[-1]: value},
                    "source_evidence_id": exchange.id,
                },
                asset=exchange.url,
                relevance=0.8,
                confidence=1,
            )
            context.add_observation(item)
            found.append(DiscoveredData(category, classification, item.id, exchange.id, path))

        def walk(value, path="$"):
            if isinstance(value, dict):
                for key, nested in value.items():
                    if key.lower() in self._fields:
                        add(*self._fields[key.lower()], f"{path}.{key}", nested)
                    if len(found) < 50:
                        walk(nested, f"{path}.{key}")
            elif isinstance(value, list):
                for index, nested in enumerate(value[:50]):
                    walk(nested, f"{path}[{index}]")

        body = exchange.json()
        if body is not None:
            walk(body)
        else:
            for match in list(re.finditer(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", exchange.body))[:20]:
                add("emails", DataClassification.SENSITIVE, "$.email", match.group())
            path = urlsplit(exchange.url).path.lower()
            if path.endswith((".bak", ".backup", ".sql")) and exchange.status == 200:
                add(
                    "backup_files",
                    DataClassification.HIGHLY_SENSITIVE,
                    "$.backup",
                    "Captured backup-like response; content must be reviewed",
                )
        return found
