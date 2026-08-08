"""Command collector.

Only commands whose full argument list matches a hard-coded allowlist entry
are executed. The allowlist is static - it is never derived from policy
content - so a compromised policy cannot inject arguments or subcommands.
"""

import shlex
import shutil
import subprocess

from app.sca.collectors.base import Collector, CollectorError, Evidence

# name -> allowed full argument tuples. Anything outside this table is refused.
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
            raise CollectorError(
                f"arguments {list(args)} are not allowed for '{name}'"
            )

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
