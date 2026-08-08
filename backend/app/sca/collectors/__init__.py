"""SCA endpoint evidence collectors.

Each collector reads one kind of evidence from the endpoint (command output,
registry value, file state, ...). Collectors never evaluate - they return
``Evidence`` and the engine evaluates it against the rule.
"""

from app.sca.collectors.base import Collector, CollectorError, Evidence
from app.sca.collectors.command import CommandCollector
from app.sca.collectors.file import FileCollector
from app.sca.collectors.process import ProcessCollector
from app.sca.collectors.registry import RegistryCollector
from app.sca.collectors.service import ServiceCollector

_COLLECTORS: dict[str, type[Collector]] = {
    CommandCollector.rule_type: CommandCollector,
    RegistryCollector.rule_type: RegistryCollector,
    FileCollector.rule_type: FileCollector,
    "directory": FileCollector,
    ProcessCollector.rule_type: ProcessCollector,
    ServiceCollector.rule_type: ServiceCollector,
}


def collect_evidence(rule, platform: str) -> Evidence:
    """Dispatch a check rule to its collector.

    Raises :class:`CollectorError` when no collector exists for the rule type
    or when the collector cannot read the endpoint.
    """
    cls = _COLLECTORS.get(rule.rule_type or "")
    if cls is None:
        raise CollectorError(f"no collector for rule type '{rule.rule_type}'")
    return cls().collect(rule, platform)


__all__ = ["Collector", "CollectorError", "Evidence", "collect_evidence"]
