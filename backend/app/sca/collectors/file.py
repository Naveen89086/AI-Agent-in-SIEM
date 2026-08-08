"""File and directory collector.

Checks existence of a path and reads its first line(s) when a ``file_path``
points to a readable text file. Absent paths are reported as not applicable
rather than failures, matching how benchmarks treat missing files.
"""

import os

from app.sca.collectors.base import Collector, CollectorError, Evidence


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
        return Evidence(
            collected=True,
            actual_value=actual,
            raw=raw,
            message="",
        )
