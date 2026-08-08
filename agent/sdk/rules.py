"""Agent-side rule model.

The agent receives a scan job as a list of these rules (one per check). Only
the fields collectors actually read are included; evaluation stays on the
server so the agent never decides PASS/FAIL.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentRule:
    check_id: str = ""
    title: str = ""
    rule_type: str = "command"
    command: str | None = None
    file_path: str | None = None
    directory_path: str | None = None
    registry_path: str | None = None
    registry_value: str | None = None
    process_name: str | None = None
    service_name: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)
