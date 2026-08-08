"""File change detection for the FIM agent.

Two complementary mechanisms, both feeding one processing pipeline:

- A ``watchdog`` filesystem observer for near-instant change notifications
  (falls back to polling-only when watchdog is not installed).
- A periodic full walk of the monitored roots, which catches anything the
  observer missed and doubles as a scheduled integrity scan.

Every observed change is turned into an evidence payload and submitted to the
manager. The agent's baseline is updated as changes are processed, so a change
re-detected by the poll does not produce a duplicate event; the manager also
dedupes on ``event_id`` as a second line of defense.
"""

import getpass
import hashlib
import logging
import os
import threading
import time
from datetime import datetime, timezone

from fim_agent.baseline import Baseline
from fim_agent.collector import (
    classify_change,
    excluded,
    file_state,
    normalize_path,
)
from fim_agent.config import FimAgentConfig
from fim_agent.transport import FimTransport, TransportError

log = logging.getLogger("fim-agent.monitor")

try:  # optional dependency; the agent degrades to polling-only
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer

    _HAS_WATCHDOG = True
except ImportError:  # pragma: no cover
    _HAS_WATCHDOG = False
    FileSystemEventHandler = object
    Observer = None


class _ChangeQueue:
    """Thread-safe bag of raw filesystem notifications."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._changes: list[dict] = []

    def push(self, kind: str, src: str, dest: str | None = None) -> None:
        with self._lock:
            self._changes.append({"kind": kind, "src": src, "dest": dest})

    def drain(self) -> list[dict]:
        with self._lock:
            items, self._changes = self._changes, []
        return items


class _FimEventHandler(FileSystemEventHandler):
    def __init__(self, queue: _ChangeQueue, exclude: list[str]) -> None:
        self.queue = queue
        self.exclude = exclude

    def _push(self, kind: str, path: str, dest: str | None = None) -> None:
        if excluded(path, self.exclude):
            return
        self.queue.push(kind, path, dest)

    def on_created(self, event) -> None:
        self._push("changed", event.src_path)

    def on_modified(self, event) -> None:
        self._push("changed", event.src_path)

    def on_deleted(self, event) -> None:
        self._push("deleted", event.src_path)

    def on_moved(self, event) -> None:
        self._push("moved", event.src_path, getattr(event, "dest_path", None))


class FimMonitor:
    def __init__(
        self,
        config: FimAgentConfig,
        transport: FimTransport | None = None,
        api_key: str | None = None,
    ) -> None:
        self.config = config
        self.transport = transport or FimTransport(config)
        self.api_key = api_key or config.load_api_key() or ""
        self.baseline = Baseline.load(config.baseline_file)
        self.queue = _ChangeQueue()
        self._observer = None
        self._stop = threading.Event()
        self._since = datetime.now(timezone.utc)
        # Never watch our own state files, even if they live under a root.
        self._state_files = {
            normalize_path(p)
            for p in (config.baseline_file, config.api_key_file)
            if p
        }
        config.exclude_patterns = list(config.exclude_patterns) + list(self._state_files)

    # ------------------------------------------------------------------ setup
    def start_observer(self) -> bool:
        """Start the watchdog observer; returns False when unavailable."""
        if not self.config.use_watchdog or not _HAS_WATCHDOG:
            log.info("watchdog unavailable - using polling-only detection")
            return False
        handler = _FimEventHandler(self.queue, self.config.exclude_patterns)
        observer = Observer()
        for root in self.config.monitored_paths:
            if os.path.isdir(root):
                observer.schedule(handler, root, recursive=True)
        observer.daemon = True
        observer.start()
        self._observer = observer
        log.info("watchdog observer started for %s", self.config.monitored_paths)
        return True

    def ensure_baseline(self) -> None:
        if not self.baseline.entries:
            log.info("building initial baseline...")
            self.baseline = self.baseline.scan(
                self.config.monitored_paths, self.config.exclude_patterns
            )
            self.baseline.save(self.config.baseline_file)
            log.info("baseline built: %d file(s)", len(self.baseline.entries))

    # -------------------------------------------------------------- change loop
    def run(self, heartbeat_thread: bool = True) -> None:
        self.ensure_baseline()
        self.start_observer()
        if heartbeat_thread:
            threading.Thread(target=self._heartbeat_loop, daemon=True).start()
        try:
            while not self._stop.is_set():
                self._process_queue()
                if self._stop.wait(self.config.poll_interval):
                    break
                self._periodic_scan()
        finally:
            if self._observer is not None:
                self._observer.stop()
                self._observer.join(timeout=2)

    def stop(self) -> None:
        self._stop.set()

    def run_once(self) -> int:
        """Process pending notifications once and return how many were sent."""
        self.ensure_baseline()
        self._process_queue()
        return self._sent

    @property
    def _sent(self) -> int:
        return self.__dict__.get("_last_sent", 0)

    # ------------------------------------------------------------------ queue
    def _process_queue(self) -> None:
        raw = self.queue.drain()
        if not raw:
            return
        self._last_sent = 0
        for item in raw:
            try:
                self._handle_raw(item)
            except Exception as exc:  # keep the loop alive on per-event errors
                log.warning("change handling failed: %s", exc)
        self.baseline.save(self.config.baseline_file)

    def _handle_raw(self, item: dict) -> None:
        kind = item["kind"]
        src = normalize_path(item["src"])
        if kind == "moved" and item.get("dest"):
            dest = normalize_path(item["dest"])
            if dest not in self.baseline.entries and src in self.baseline.entries:
                self._report_renamed(src, dest)
                return
            self._evaluate(dest)
            self._evaluate(src)
        elif kind == "deleted":
            self._evaluate(src)
        else:
            self._evaluate(src)

    # ----------------------------------------------------------- classification
    def _evaluate(self, path: str) -> None:
        """Compare one path's disk state to the baseline and report if changed."""
        if excluded(path, self.config.exclude_patterns):
            return
        current = file_state(path)
        prev = self.baseline.entries.get(normalize_path(path))
        kind = classify_change(path, prev, current)
        if kind == "added":
            self._report("added", current["path"], sha256=current["sha256"], state=current)
            self.baseline.entries[normalize_path(path)] = current
        elif kind == "deleted":
            self._report(
                "deleted", normalize_path(path), old_sha256=(prev or {}).get("sha256")
            )
            self.baseline.entries.pop(normalize_path(path), None)
        elif kind == "modified":
            self._report(
                "modified",
                current["path"],
                sha256=current["sha256"],
                old_sha256=(prev or {}).get("sha256"),
                state=current,
            )
            self.baseline.entries[normalize_path(path)] = current

    def _report_renamed(self, old_path: str, new_path: str) -> None:
        prev = self.baseline.entries.get(old_path)
        current = file_state(new_path)
        if current is None:
            self._evaluate(old_path)  # both gone / unknown - fall through
            return
        self._report(
            "renamed",
            current["path"],
            sha256=current["sha256"],
            old_sha256=(prev or {}).get("sha256"),
            old_path=old_path,
            state=current,
        )
        self.baseline.entries.pop(old_path, None)
        self.baseline.entries[normalize_path(new_path)] = current

    def _report(
        self,
        event_type: str,
        path: str,
        *,
        sha256: str | None = None,
        old_sha256: str | None = None,
        old_path: str | None = None,
        state: dict | None = None,
    ) -> None:
        if not self.api_key:
            log.warning("no API key - cannot send '%s' for %s", event_type, path)
            return
        state = state or {}
        event_id = self._event_id(event_type, path, sha256, old_path, old_sha256)
        payload = {
            "agent_code": self.config.agent_code,
            "event_type": event_type,
            "path": path,
            "sha256": sha256,
            "old_sha256": old_sha256,
            "new_sha256": sha256 if event_type == "modified" else None,
            "old_path": old_path,
            "size": state.get("size", 0),
            "modified_time": state.get("mtime"),
            "user": getpass.getuser(),
            "user_id": os.environ.get("USERNAME", getpass.getuser()),
            "file_type": state.get("file_type"),
            "source": "fim-agent",
            "event_id": event_id,
        }
        try:
            result = self.transport.ingest(self.api_key, payload)
            log.info(
                "sent %s for %s -> accepted=%s type=%s severity=%s",
                event_type,
                path,
                result.get("accepted"),
                result.get("event_type"),
                result.get("severity"),
            )
            self._last_sent = getattr(self, "_last_sent", 0) + 1
        except TransportError as exc:
            log.warning("ingest failed for %s: %s", path, exc)

    @staticmethod
    def _event_id(
        event_type: str,
        path: str,
        sha256: str | None,
        old_path: str | None,
        old_sha256: str | None,
    ) -> str:
        key = "|".join([event_type, path, old_path or "", sha256 or "", old_sha256 or ""])
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    # -------------------------------------------------------------------- scan
    def _periodic_scan(self) -> None:
        fresh = self.baseline.scan(
            self.config.monitored_paths, self.config.exclude_patterns
        )
        added, removed, modified = self.baseline.diff(fresh)
        if not added and not removed and not modified:
            return
        for path in removed:
            self._report("deleted", path, old_sha256=self.baseline.entries[path].get("sha256"))
        for path in added:
            state = fresh.entries[path]
            self._report("added", path, sha256=state["sha256"], state=state)
        for path in modified:
            state = fresh.entries[path]
            self._report(
                "modified",
                path,
                sha256=state["sha256"],
                old_sha256=self.baseline.entries[path].get("sha256"),
                state=state,
            )
        self.baseline = fresh
        self.baseline.save(self.config.baseline_file)

    # ---------------------------------------------------------------- heartbeat
    def _heartbeat_loop(self) -> None:
        if not self.api_key:
            return
        interval = max(10.0, self.config.heartbeat_interval)
        while not self._stop.is_set():
            try:
                self.transport.heartbeat(self.api_key, status="online")
            except TransportError as exc:
                log.warning("heartbeat failed: %s", exc)
            self._stop.wait(interval)
