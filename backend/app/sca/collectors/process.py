"""Process collector.

Checks whether a named process image is running on the endpoint. Windows-only
``tasklist`` is invoked with an argv list (no shell) and the image name is
validated against a strict allowlist pattern so a compromised policy cannot
inject filter conditions. Other platforms raise ``CollectorError`` so the
check is recorded as an error rather than a fabricated pass/fail.
"""

import re
import subprocess
import sys

from app.sca.collectors.base import Collector, CollectorError, Evidence

# Image names are file names: letters, digits, '.', '_', '-'. Anything else is
# refused so a rule cannot smuggle additional /FI filter clauses.
_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")

_TIMEOUT_SECONDS = 10


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
        if "INFO: No tasks" in output or not output:
            running = False
        else:
            running = name.lower() in output.lower()
        return Evidence(
            collected=True,
            actual_value="running" if running else "not running",
            raw={
                "source": "Process collector",
                "process_name": name,
                "running": running,
            },
        )
