"""Windows registry collector.

Reads a registry value from the local hive. Only runs on Windows endpoints;
on other platforms it raises ``CollectorError`` so the check is recorded as an
error rather than a fabricated pass/fail.
"""

import sys

from app.sca.collectors.base import Collector, CollectorError, Evidence


class RegistryCollector(Collector):
    rule_type = "registry"

    def collect(self, rule, platform):
        if sys.platform != "win32":
            raise CollectorError("registry collector requires a Windows endpoint")
        if not rule.registry_path:
            raise CollectorError("registry rule has no registry_path")

        import winreg

        path = rule.registry_path
        value_name = rule.registry_value or ""
        hive_name, _, rest = path.partition("\\")
        hive = getattr(winreg, hive_name, None)
        if not isinstance(hive, int):
            raise CollectorError(f"unknown registry hive '{hive_name}'")

        try:
            with winreg.OpenKey(hive, rest) as key:
                value, value_type = winreg.QueryValueEx(key, value_name)
        except FileNotFoundError:
            return Evidence(
                collected=True,
                actual_value="absent",
                not_applicable=True,
                raw={"registry_path": path, "registry_value": value_name, "present": False},
                message="registry value not found",
            )
        except PermissionError:
            raise CollectorError("permission denied reading registry")

        return Evidence(
            collected=True,
            actual_value=str(value),
            raw={"registry_path": path, "registry_value": value_name, "present": True},
        )
