"""Baseline snapshot for the FIM agent.

A plain JSON map ``path -> {sha256, size, mtime, file_type}`` persisted so the
agent only reports *changes* relative to its last known state. The manager
keeps its own authoritative baseline; the local file is just the agent's
reference point for change detection and resume.
"""

import json
import os

from fim_agent.collector import excluded, file_state, normalize_path


class Baseline:
    def __init__(self, entries: dict | None = None) -> None:
        self.entries: dict[str, dict] = entries or {}

    # ------------------------------------------------------------ persistence
    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.entries, fh, indent=2, sort_keys=True)

    @classmethod
    def load(cls, path: str) -> "Baseline":
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return cls()
        if not isinstance(raw, dict):
            return cls()
        return cls({normalize_path(k): v for k, v in raw.items()})

    # ---------------------------------------------------------------- walking
    def scan(
        self,
        roots: list[str],
        exclude_patterns: list[str] | None = None,
    ) -> "Baseline":
        """Rebuild the baseline by walking the monitored roots."""
        fresh: dict[str, dict] = {}
        for root in roots:
            if not os.path.isdir(root):
                continue
            for dirpath, dirnames, filenames in os.walk(root):
                # prune excluded directories
                dirnames[:] = [
                    d for d in dirnames if not excluded(os.path.join(dirpath, d), exclude_patterns)
                ]
                for name in filenames:
                    full = os.path.join(dirpath, name)
                    if excluded(full, exclude_patterns):
                        continue
                    state = file_state(full)
                    if state is not None:
                        fresh[state["path"]] = state
        return Baseline(fresh)

    def diff(self, other: "Baseline") -> tuple[list[dict], list[dict], list[dict]]:
        """Return (added, removed, modified) entry names between self and other.

        ``self`` is the old baseline, ``other`` the fresh one.
        """
        added = [p for p in other.entries if p not in self.entries]
        removed = [p for p in self.entries if p not in other.entries]
        modified = [
            p
            for p in self.entries
            if p in other.entries
            and self.entries[p].get("sha256") != other.entries[p].get("sha256")
        ]
        return added, removed, modified
