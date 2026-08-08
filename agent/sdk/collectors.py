"""Allowlisted evidence collectors.

The command allowlist is static - it is never derived from policy content - so
a compromised or malicious scan job cannot inject arguments or subcommands.
This file must stay in sync with ``backend/app/sca/collectors/*``.
"""

import os
import re
import shlex
import shutil
import subprocess
import sys

from agent.sdk.base import Collector, CollectorError, Evidence

_ALLOWED_COMMANDS: dict[str, list[tuple[str, ...]]] = {
    "net": [
        ("accounts",),
        ("accounts", "/domain"),
        ("user", "guest"),
        ("user", "Administrator"),
    ],
    "net.exe": [
        ("accounts",),
        ("accounts", "/domain"),
        ("user", "guest"),
        ("user", "Administrator"),
    ],
    "auditpol": [("/get", "/category:*")],
    "auditpol.exe": [("/get", "/category:*")],
    "powershell": [("-NoProfile", "-Command", "Get-MpPreference")],
    "powershell.exe": [("-NoProfile", "-Command", "Get-MpPreference")],
    "systeminfo": [()],
    "uname": [("-a",)],
}

_EXECUTABLE_ALIASES = {
    "net.exe": "net",
    "auditpol.exe": "auditpol",
    "powershell.exe": "powershell",
}

_TIMEOUT_SECONDS = 10
_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")


class CommandCollector(Collector):
    rule_type = "command"

    def collect(self, rule, platform):
        command = (rule.command or "").strip()
        if not command:
            raise CollectorError("command rule has no command")
        try:
            tokens = shlex.split(command)
        except ValueError as exc:
            raise CollectorError(f"invalid command: {exc}")
        if not tokens:
            raise CollectorError("command rule has an empty command")

        name = tokens[0].lower()
        args = tuple(tokens[1:])
        allowed_args = _ALLOWED_COMMANDS.get(name)
        if allowed_args is None:
            raise CollectorError(f"command '{name}' is not allowlisted")
        if args not in allowed_args:
            raise CollectorError(f"arguments {list(args)} are not allowed for '{name}'")

        executable = shutil.which(_EXECUTABLE_ALIASES.get(name, name))
        if executable is None:
            raise CollectorError(f"executable '{name}' not found")

        try:
            proc = subprocess.run(
                [executable, *args],
                capture_output=True,
                text=True,
                timeout=_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            raise CollectorError("command timed out")

        output = (proc.stdout or "").strip() or (proc.stderr or "").strip()
        return Evidence(
            collected=True,
            actual_value=output,
            raw={
                "source": "Command collector",
                "command": " ".join([name, *args]),
                "exit_code": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
            },
        )


class FileCollector(Collector):
    rule_type = "file"

    def collect(self, rule, platform):
        path = rule.file_path or rule.directory_path
        if not path:
            raise CollectorError("file rule has no file_path/directory_path")
        if not os.path.exists(path):
            return Evidence(
                collected=True,
                actual_value="absent",
                not_applicable=True,
                raw={"path": path, "exists": False},
                message="path does not exist",
            )
        raw: dict = {"path": path, "exists": True}
        actual = "present"
        try:
            if os.path.isfile(path):
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    head = fh.read(4096).strip()
                raw["head"] = head
                raw["size"] = os.path.getsize(path)
                if head:
                    actual = head
        except OSError as exc:
            raise CollectorError(f"cannot read path: {exc}")
        return Evidence(collected=True, actual_value=actual, raw=raw, message="")


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


class ProcessCollector(Collector):
    rule_type = "process"

    def collect(self, rule, platform):
        name = (getattr(rule, "process_name", None) or "").strip()
        if not name:
            raise CollectorError("process rule has no process_name")
        if not _NAME_RE.match(name):
            raise CollectorError(f"invalid process_name '{name}'")
        if sys.platform != "win32":
            raise CollectorError("process collector requires a Windows endpoint")
        try:
            proc = subprocess.run(
                ["tasklist", "/FI", f"IMAGENAME eq {name}", "/NH"],
                capture_output=True,
                text=True,
                timeout=_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise CollectorError(f"cannot query processes: {exc}")
        output = (proc.stdout or "").strip()
        running = bool(output) and "INFO: No tasks" not in output and name.lower() in output.lower()
        return Evidence(
            collected=True,
            actual_value="running" if running else "not running",
            raw={"source": "Process collector", "process_name": name, "running": running},
        )


class ServiceCollector(Collector):
    rule_type = "service"

    def collect(self, rule, platform):
        name = (getattr(rule, "service_name", None) or "").strip()
        if not name:
            raise CollectorError("service rule has no service_name")
        if not _NAME_RE.match(name):
            raise CollectorError(f"invalid service_name '{name}'")
        if sys.platform != "win32":
            raise CollectorError("service collector requires a Windows endpoint")
        try:
            proc = subprocess.run(
                ["sc", "query", name],
                capture_output=True,
                text=True,
                timeout=_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise CollectorError(f"cannot query service: {exc}")
        output = (proc.stdout or "").strip() or (proc.stderr or "").strip()
        if "does not exist" in output.lower() or "1060" in output:
            return Evidence(
                collected=True,
                actual_value="absent",
                not_applicable=True,
                raw={"source": "Service collector", "service_name": name, "exists": False},
                message="service does not exist",
            )
        upper = output.upper()
        if "RUNNING" in upper:
            state = "running"
        elif "STOPPED" in upper:
            state = "stopped"
        else:
            state = "unknown"
        return Evidence(
            collected=True,
            actual_value=state,
            raw={"source": "Service collector", "service_name": name, "state": state},
        )


_COLLECTORS: dict[str, type[Collector]] = {
    CommandCollector.rule_type: CommandCollector,
    RegistryCollector.rule_type: RegistryCollector,
    FileCollector.rule_type: FileCollector,
    "directory": FileCollector,
    ProcessCollector.rule_type: ProcessCollector,
    ServiceCollector.rule_type: ServiceCollector,
}


def collect_evidence(rule, platform: str) -> Evidence:
    """Dispatch a rule to its collector.

    Raises :class:`CollectorError` when no collector exists for the rule type
    or when the collector cannot read the endpoint.
    """
    cls = _COLLECTORS.get(rule.rule_type or "")
    if cls is None:
        raise CollectorError(f"no collector for rule type '{rule.rule_type}'")
    return cls().collect(rule, platform)
