"""Safety Policy Definition (V10 Evidence-Driven Validation Architecture).

Enforces strict boundaries against destructive actions, denial of service,
and uncontrolled payload sizes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class SafetyPolicy:
    """Safety constraints enforced during automated vulnerability validation."""
    max_requests_per_target: int = 50
    max_concurrency: int = 5
    max_duration_seconds: float = 30.0
    max_payload_size_bytes: int = 65536  # 64 KB
    max_retries: int = 2
    destructive_actions_allowed: bool = False
    resource_exhaustion_allowed: bool = False
    abort_threshold_errors: int = 5
    blacklisted_commands: List[str] = field(
        default_factory=lambda: [
            "rm ", "rmdir", "del ", "erase", "mkfs", "dd ", "shutdown", "reboot",
            "format", "drop table", "truncate table", "delete from", ":(){ :|:& };:",
            "> /dev/sd", "chmod -R 777 /", "chown -R"
        ]
    )

    def is_safe_command(self, cmd: str) -> bool:
        """Verifies command contains no dangerous or destructive primitives."""
        cmd_lower = cmd.lower()
        for bl in self.blacklisted_commands:
            if bl in cmd_lower:
                return False
        return True
