"""Windows service collector.

Reads the state of a named service via ``sc query`` (argv list, no shell). The
service name is validated against a strict pattern so a rule cannot inject
additional arguments. A service that does not exist is reported as not
applicable; other platforms raise ``CollectorError``.
"""

import re
import subprocess
import sys

from app.sca.collectors.base import Collector, CollectorError, Evidence

_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")

_TIMEOUT_SECONDS = 10


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
            raw={
                "source": "Service collector",
                "service_name": name,
                "state": state,
                "exit_code": proc.returncode,
            },
        )
