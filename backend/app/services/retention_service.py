"""Log retention & storage service (function 9).

Implements the retention policy for both backends:
  - Elasticsearch: ILM lifecycle (hot rollover + delete), snapshot repository
    and snapshot creation for backup/restore.
  - Local JSON store: cleanup of per-day files older than the delete window.
"""

import logging
from datetime import datetime, timezone
from pathlib import Path

from app.core.config import settings
from app.storage.base import build_log_store

log = logging.getLogger("siem.retention")

_LIFECYCLE_NAME = "siem-lifecycle"
_SNAPSHOT_REPO = "siem-backups"
_SNAPSHOT_NAME = "siem-snapshot"


def build_lifecycle_policy(retention_delete_days: int) -> dict:
    return {
        "policy": {
            "phases": {
                "hot": {
                    "min_age": "0ms",
                    "actions": {"rollover": {"max_age": "1d"}, "set_priority": {"priority": 100}},
                },
                "delete": {
                    "min_age": f"{retention_delete_days}d",
                    "actions": {"delete": {}},
                },
            }
        }
    }


class RetentionService:
    def __init__(self) -> None:
        self.store = build_log_store()

    # ---------------------------------------------------------------- status
    def status(self) -> dict:
        return {
            "backend": type(self.store).__name__,
            "retention_hot_days": settings.retention_hot_days,
            "retention_warm_days": settings.retention_warm_days,
            "retention_cold_days": settings.retention_cold_days,
            "retention_delete_days": settings.retention_delete_days,
            "lifecycle_policy": _LIFECYCLE_NAME,
            "snapshot_repository": _SNAPSHOT_REPO,
        }

    # -------------------------------------------------------------- apply ILM
    async def _es_apply_policy(self, es) -> dict:
        lifecycle = build_lifecycle_policy(settings.retention_delete_days)
        result: dict = {}
        try:
            await es.ilm.put_lifecycle(name=_LIFECYCLE_NAME, policy=lifecycle)
            result["lifecycle"] = "updated"
        except Exception:
            log.exception("ILM policy update failed")
            result["lifecycle"] = "failed"
        try:
            await es.indices.rollover(alias=f"{self.store.prefix}-events", max_age="1d")
            result["rollover"] = "triggered"
        except Exception:
            result["rollover"] = "no-alias-or-skipped"
        return result

    async def _es_snapshot(self, es) -> dict:
        try:
            await es.snapshot.create_repository(
                name=_SNAPSHOT_REPO,
                body={"type": "fs", "settings": {"location": "./backups"}},
            )
            repo_status = "ready"
        except Exception:
            log.exception("Snapshot repository registration failed")
            repo_status = "failed-or-exists"
        try:
            await es.snapshot.create(
                repository=_SNAPSHOT_REPO,
                snapshot=_SNAPSHOT_NAME,
                wait_for_completion=False,
                body={"indices": f"{self.store.prefix}-*"},
            )
            snapshot = "started"
        except Exception:
            log.exception("Snapshot creation failed")
            snapshot = "failed-or-exists"
        return {"repository": repo_status, "snapshot": snapshot}

    # ------------------------------------------------------------- local path
    def _local_cleanup(self) -> int:
        """Delete local JSONL event files older than the delete window."""
        deleted = 0
        base_dir = Path(self.store.base_dir)
        cutoff = datetime.now(timezone.utc).timestamp() - settings.retention_delete_days * 86400
        for file in base_dir.glob("events-*.jsonl"):
            try:
                if file.stat().st_mtime < cutoff:
                    file.unlink()
                    deleted += 1
            except OSError:
                continue
        return deleted

    # ------------------------------------------------------------------- run
    async def run(self) -> dict:
        report: dict = {"at": datetime.now(timezone.utc).isoformat(), "actions": {}}
        if type(self.store).__name__ == "ElasticsearchStore":
            report["actions"]["policy"] = await self._es_apply_policy(self.store._client)
            report["actions"]["snapshot"] = await self._es_snapshot(self.store._client)
        else:
            deleted = self._local_cleanup()
            report["actions"]["local_cleanup"] = {"files_deleted": deleted}
        return report

    async def snapshot(self) -> dict:
        if type(self.store).__name__ == "ElasticsearchStore":
            return await self._es_snapshot(self.store._client)
        return {"repository": "n/a", "snapshot": "local-store-does-not-need-snapshots"}
