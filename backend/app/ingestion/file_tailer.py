"""File tailer collector (Filebeat-style).

Tails configured log files, tracking read offsets so restarts resume where
they left off. Supports full-file watch or `tail -f` style.
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from app.pipeline.bus import EventBus, Topics, stamp

log = logging.getLogger("siem.ingest.tailer")


class FileTailer:
    """Poll-based file watcher that ships new lines to the event bus."""

    def __init__(
        self,
        bus: EventBus,
        *,
        paths: list[str] | None = None,
        source_name: str = "file",
        offset_file: str = "./data/tailer_offsets.json",
        poll_seconds: float = 1.0,
        encoding: str = "utf-8",
        errors: str = "replace",
    ) -> None:
        self.bus = bus
        self.paths = paths or []
        self.source_name = source_name
        self.offset_file = Path(offset_file)
        self.poll_seconds = poll_seconds
        self.encoding = encoding
        self.errors = errors
        self._offsets: dict[str, int] = self._load_offsets()

    def _load_offsets(self) -> dict[str, int]:
        if not self.offset_file.exists():
            return {}
        try:
            data = json.loads(self.offset_file.read_text(encoding="utf-8"))
            return {k: int(v) for k, v in data.items()}
        except Exception:
            return {}

    def _save_offsets(self) -> None:
        try:
            self.offset_file.parent.mkdir(parents=True, exist_ok=True)
            self.offset_file.write_text(
                json.dumps(self._offsets), encoding="utf-8"
            )
        except Exception:
            log.warning("Could not persist tailer offsets")

    async def _tail_file(self, path_str: str) -> None:
        path = Path(path_str)
        if not path.exists():
            return
        try:
            offset = self._offsets.get(path_str, 0)
            size = path.stat().st_size
            if size < offset:
                # file rotated/truncated
                offset = 0
            with path.open("r", encoding=self.encoding, errors=self.errors) as fh:
                fh.seek(offset)
                for line in fh:
                    line = line.rstrip("\r\n")
                    if not line:
                        continue
                    await self._publish(path_str, line)
                    offset = fh.tell()
            self._offsets[path_str] = offset
            self._save_offsets()
        except PermissionError:
            pass
        except Exception:
            log.exception("Failed tailing %s", path_str)

    async def _publish(self, path: str, line: str) -> None:
        raw = stamp(
            {
                "raw": line,
                "source_type": "file",
                "source_name": f"{self.source_name}:{path}",
                "host": os.uname().nodename if hasattr(os, "uname") else "localhost",
                "message": line,
                "extra": {"path": path},
                "tags": ["file"],
                "received_at": datetime.now(timezone.utc).isoformat(),
                "pipeline": {"ingested": True, "normalized": False},
            }
        )
        await self.bus.publish(Topics.RAW_EVENTS, raw)

    async def run(self) -> None:
        log.info("File tailer watching %d paths", len(self.paths))
        while True:
            for path in self.paths:
                await self._tail_file(path)
            await asyncio.sleep(self.poll_seconds)
