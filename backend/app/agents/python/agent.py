#!/usr/bin/env python3
"""SIEM Endpoint Agent (Python).

Cross-platform collector that tails local log files (and on Windows can pull
the Security event log) and ships events to the SIEM HTTP collector.

Usage:
    python agent.py --collector http://localhost:8000/api/v1/ingest/events \
                    --files /var/log/auth.log --interval 30
"""

import argparse
import json
import os
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import httpx
except ImportError:
    httpx = None


class EndpointAgent:
    def __init__(self, collector: str, source_name: str, files: list[str], interval: float) -> None:
        self.collector = collector
        self.source_name = source_name
        self.files = files
        self.interval = interval
        self.offsets: dict[str, int] = {}
        self._http = httpx.Client(timeout=15.0) if httpx else None

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _host(self) -> str:
        return platform.node() or "localhost"

    def _ship(self, events: list[dict[str, Any]]) -> None:
        if not events:
            return
        payload = {"events": events}
        if self._http is None:
            print("httpx not installed; printing events", file=sys.stderr)
            for e in events:
                print(json.dumps(e))
            return
        try:
            resp = self._http.post(self.collector, json=payload)
            resp.raise_for_status()
        except Exception as exc:
            print(f"WARN: failed to ship {len(events)} events: {exc}", file=sys.stderr)

    # ---------------------------------------------------------------- collectors
    def _tail_files(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        for path_str in self.files:
            path = Path(path_str)
            if not path.exists():
                continue
            try:
                offset = self.offsets.get(path_str, 0)
                size = path.stat().st_size
                if size < offset:
                    offset = 0
                with path.open("r", encoding="utf-8", errors="replace") as fh:
                    fh.seek(offset)
                    for line in fh:
                        line = line.rstrip("\r\n")
                        if not line:
                            continue
                        events.append(
                            {
                                "message": line[:4000],
                                "source_type": "file",
                                "source_name": f"{self.source_name}:{path_str}",
                                "host": self._host(),
                                "timestamp": self._now(),
                                "extra": {"path": path_str},
                                "tags": ["file"],
                            }
                        )
                        offset = fh.tell()
                self.offsets[path_str] = offset
            except Exception as exc:
                print(f"WARN: tail {path_str}: {exc}", file=sys.stderr)
        return events

    def _windows_security_log(self) -> list[dict[str, Any]]:
        if platform.system() != "Windows":
            return []
        # Best-effort: forward recent Security log entries via PowerShell shim.
        try:
            import subprocess

            script = (
                "Get-WinEvent -FilterHashtable @{LogName='Security';StartTime=(Get-Date).AddMinutes(-5)} "
                "-MaxEvents 100 -ErrorAction SilentlyContinue | Select-Object -First 100 | "
                "ConvertTo-Json -Depth 3 -Compress"
            )
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command", script],
                capture_output=True, text=True, timeout=30,
            )
            data = json.loads(out.stdout or "[]")
            if isinstance(data, dict):
                data = [data]
            events = []
            for rec in data:
                events.append(
                    {
                        "message": (rec.get("Message") or "")[:4000],
                        "source_type": "windows",
                        "source_name": self.source_name,
                        "host": rec.get("MachineName") or self._host(),
                        "timestamp": rec.get("TimeCreated") or self._now(),
                        "extra": {
                            "event_id": rec.get("Id"),
                            "provider": rec.get("ProviderName"),
                            "log_name": rec.get("LogName"),
                            "record_id": rec.get("RecordId"),
                        },
                        "tags": ["windows", "security"],
                    }
                )
            return events
        except Exception:
            return []

    # ---------------------------------------------------------------------- run
    def run(self) -> None:
        print(f"SIEM agent '{self.source_name}' started (collector={self.collector})")
        while True:
            events = self._tail_files() + self._windows_security_log()
            self._ship(events)
            time.sleep(self.interval)


def main() -> None:
    parser = argparse.ArgumentParser(description="SIEM endpoint agent")
    parser.add_argument("--collector", default=os.environ.get("SIEM_COLLECTOR", "http://localhost:8000/api/v1/ingest/events"))
    parser.add_argument("--source-name", default=os.environ.get("SIEM_SOURCE_NAME", platform.node() or "agent"))
    parser.add_argument("--files", nargs="*", default=os.environ.get("SIEM_FILES", "").split(",") if os.environ.get("SIEM_FILES") else [])
    parser.add_argument("--interval", type=float, default=float(os.environ.get("SIEM_INTERVAL", "30")))
    args = parser.parse_args()
    EndpointAgent(args.collector, args.source_name, args.files, args.interval).run()


if __name__ == "__main__":
    main()
