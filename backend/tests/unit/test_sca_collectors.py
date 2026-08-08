"""SCA - collector tests (server + agent SDK).

Collectors must return real evidence and refuse anything outside the static
allowlist. Malicious or non-allowlisted commands are rejected, never executed.
"""

import pytest

from app.sca.collectors import (
    CommandCollector,
    CollectorError,
    Evidence,
    FileCollector,
    RegistryCollector,
    collect_evidence,
)

# The standalone agent package (project root) must stay in lockstep with the
# server collectors; the same evidence contract is tested on both sides.
from agent.sdk.base import CollectorError as AgentCollectorError  # noqa: E402
from agent.sdk.collectors import CommandCollector as AgentCommandCollector  # noqa: E402
from agent.sdk.collectors import FileCollector as AgentFileCollector  # noqa: E402
from agent.sdk.collectors import collect_evidence as agent_collect_evidence  # noqa: E402
from agent.sdk.rules import AgentRule  # noqa: E402


class _Rule:
    def __init__(self, **kwargs):
        self.rule_type = kwargs.get("rule_type", "command")
        self.command = kwargs.get("command")
        self.file_path = kwargs.get("file_path")
        self.directory_path = kwargs.get("directory_path")
        self.registry_path = kwargs.get("registry_path")
        self.registry_value = kwargs.get("registry_value")
        self.expected_value = kwargs.get("expected_value")
        self.operator = kwargs.get("operator", "eq")


def _rule(**kwargs):
    return _Rule(**kwargs)


# ------------------------------------------------------------------ commands
def test_allowlisted_command_runs_without_arguments():
    evidence = CommandCollector().collect(_rule(rule_type="command", command="systeminfo"), "windows")
    assert evidence.collected is True
    assert "OS" in evidence.actual_value or "Host" in evidence.actual_value


def test_allowlisted_command_with_arguments_runs():
    evidence = CommandCollector().collect(
        _rule(rule_type="command", command="net accounts"), "windows"
    )
    assert evidence.collected is True
    assert evidence.actual_value.strip()


@pytest.mark.parametrize(
    "command",
    [
        "net accounts; rm -rf /",
        "net accounts | cmd",
        "net && whoami",
        "whoami",
        "powershell -Command Get-FileHash /etc/passwd",
        "net user administrator /active:yes",
        "rm -rf /",
        "",
        "net 'accounts; dangerous'",
    ],
)
def test_command_injection_and_non_allowlisted_are_refused(command):
    with pytest.raises(CollectorError):
        CommandCollector().collect(_rule(rule_type="command", command=command), "windows")


def test_unknown_rule_type_dispatch_fails():
    with pytest.raises(CollectorError):
        collect_evidence(_rule(rule_type="bogus", command="net accounts"), "windows")


# ---------------------------------------------------------------------- files
def test_file_collector_reads_existing_file(tmp_path):
    target = tmp_path / "audit.txt"
    target.write_text("enabled\n", encoding="utf-8")
    evidence = FileCollector().collect(
        _rule(rule_type="file", file_path=str(target)), "windows"
    )
    assert evidence.collected is True
    assert evidence.actual_value == "enabled"
    assert evidence.not_applicable is False


def test_file_collector_missing_path_is_not_applicable(tmp_path):
    evidence = FileCollector().collect(
        _rule(rule_type="file", file_path=str(tmp_path / "missing.txt")), "windows"
    )
    assert evidence.collected is True
    assert evidence.not_applicable is True
    assert evidence.actual_value == "absent"


# ------------------------------------------------------------------- registry
def test_registry_collector_rejects_unknown_hive():
    with pytest.raises(CollectorError):
        RegistryCollector().collect(
            _rule(
                rule_type="registry",
                registry_path="HKLM\\Software\\Whatever",
                registry_value="x",
            ),
            "windows",
        )


# ------------------------------------------------------------- agent SDK parity
def test_agent_sdk_matches_server_contract():
    rule = _rule(rule_type="command", command="net accounts")
    evidence = CommandCollector().collect(rule, "windows")
    agent_rule = AgentRule(rule_type="command", command="net accounts")
    agent_evidence = AgentCommandCollector().collect(agent_rule, "windows")
    assert agent_evidence.collected == evidence.collected is True
    assert agent_evidence.actual_value == evidence.actual_value


def test_agent_sdk_allowlist_rejects_injection():
    agent_rule = AgentRule(rule_type="command", command="net accounts; rm -rf /")
    with pytest.raises(AgentCollectorError):
        AgentCommandCollector().collect(agent_rule, "windows")


def test_agent_sdk_missing_file_not_applicable(tmp_path):
    agent_rule = AgentRule(
        rule_type="file", file_path=str(tmp_path / "nope.txt")
    )
    evidence = AgentFileCollector().collect(agent_rule, "windows")
    assert evidence.not_applicable is True


def test_agent_sdk_dispatch_unknown_type():
    with pytest.raises(AgentCollectorError):
        agent_collect_evidence(AgentRule(rule_type="bogus"), "windows")


def test_evidence_defaults():
    evidence = Evidence()
    assert evidence.collected is False
    assert evidence.actual_value is None
    assert evidence.not_applicable is False
    assert evidence.raw == {}
    assert evidence.message == ""
