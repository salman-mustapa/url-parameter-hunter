"""Disposable Lab Environment Manager (V8 §45).

Manages isolated, disposable environments for high-risk adversary simulation and advanced exploit verification:
- Targets & isolated containers
- Network services & vulnerable web applications
- Identity & database fixtures
- Attack simulation fixtures
- Automated evidence collection & teardown
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("services.lab_manager")


@dataclass
class LabEnvironmentFixture:
    id: str
    name: str
    description: str
    is_active: bool = True
    is_disposable: bool = True
    targets: List[Dict[str, Any]] = field(default_factory=list)
    configs: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class LabEnvironmentManager:
    """Manages disposable lab fixtures for safe adversary emulation (V8 §45)."""

    def __init__(self) -> None:
        self._labs: Dict[str, LabEnvironmentFixture] = {}
        self._create_default_fixtures()

    def _create_default_fixtures(self) -> None:
        default_lab = LabEnvironmentFixture(
            id="lab_default_sandbox",
            name="Default Security Assessment Lab",
            description="Isolated disposable sandbox for authorized adversary simulation and L4 execution testing.",
            is_active=True,
            is_disposable=True,
            targets=[
                {
                    "name": "vulnerable_web_app",
                    "service": "http",
                    "ip": "127.0.0.1",
                    "port": 8088,
                    "profile": "wordpress_test_fixture",
                },
                {
                    "name": "internal_db_service",
                    "service": "mysql",
                    "ip": "127.0.0.1",
                    "port": 33066,
                    "profile": "mysql_test_fixture",
                },
            ],
            configs={"network_isolation": "strict", "cleanup_on_completion": True},
        )
        self._labs[default_lab.id] = default_lab

    def create_lab_environment(
        self,
        name: str,
        description: str = "",
        targets: Optional[List[Dict[str, Any]]] = None,
        configs: Optional[Dict[str, Any]] = None,
    ) -> LabEnvironmentFixture:
        """Spawns a new disposable lab environment."""
        lab_id = f"lab_{uuid.uuid4().hex[:8]}"
        lab = LabEnvironmentFixture(
            id=lab_id,
            name=name,
            description=description,
            is_active=True,
            is_disposable=True,
            targets=targets or [],
            configs=configs or {},
        )
        self._labs[lab_id] = lab
        logger.info("Created disposable lab environment %s: '%s' (%d targets)", lab_id, name, len(lab.targets))
        return lab

    def get_lab(self, lab_id: str) -> Optional[LabEnvironmentFixture]:
        return self._labs.get(lab_id)

    def list_labs(self) -> List[Dict[str, Any]]:
        return [
            {
                "id": l.id,
                "name": l.name,
                "description": l.description,
                "is_active": l.is_active,
                "is_disposable": l.is_disposable,
                "targets_count": len(l.targets),
                "targets": l.targets,
                "created_at": l.created_at,
            }
            for l in self._labs.values()
        ]

    def teardown_lab(self, lab_id: str) -> bool:
        """Tears down and destroys a disposable lab environment."""
        if lab_id in self._labs:
            self._labs.pop(lab_id)
            logger.info("Teardown and destroyed disposable lab environment: %s", lab_id)
            return True
        return False


lab_manager = LabEnvironmentManager()
