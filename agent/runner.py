"""Local scan job runner.

Runs a list of rules through the allowlisted collectors and returns structured
evidence records. The agent never evaluates - PASS/FAIL stays on the server.
"""

import platform
import sys
from typing import Any

from agent.sdk import AgentRule, Evidence, collect_evidence


def run_scan(rules: list[AgentRule], os_platform: str = "") -> list[dict[str, Any]]:
    """Collect evidence for every rule; errors become records, not crashes."""
    target_platform = os_platform or (platform.system().lower())
    records: list[dict[str, Any]] = []
    for rule in rules:
        try:
            evidence = collect_evidence(rule, target_platform)
            records.append(
                {
                    "check_id": rule.check_id,
                    "title": rule.title,
                    "rule_type": rule.rule_type,
                    "collected": evidence.collected,
                    "actual_value": evidence.actual_value,
                    "not_applicable": evidence.not_applicable,
                    "evidence": evidence.raw,
                    "message": evidence.message,
                }
            )
        except Exception as exc:  # noqa: BLE001 - a bad rule must not abort the run
            records.append(
                {
                    "check_id": rule.check_id,
                    "title": rule.title,
                    "rule_type": rule.rule_type,
                    "collected": False,
                    "actual_value": None,
                    "not_applicable": False,
                    "evidence": {"error": str(exc)},
                    "message": str(exc)[:300],
                }
            )
    return records


def rules_from_dicts(payloads: list[dict]) -> list[AgentRule]:
    return [AgentRule(**{k: v for k, v in p.items() if k in AgentRule.__dataclass_fields__}) for p in payloads]


def evidence_to_dict(evidence: Evidence) -> dict[str, Any]:
    return {
        "collected": evidence.collected,
        "actual_value": evidence.actual_value,
        "not_applicable": evidence.not_applicable,
        "evidence": evidence.raw,
        "message": evidence.message,
    }
