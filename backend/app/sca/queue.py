"""In-memory SCA scan job queue.

A small background thread pool consumes queued scan ids and runs the
``ScanEngine`` against a fresh database session. This is the local
replacement for Redis/Celery: the queue interface (``enqueue``/``start``/
``stop``) is stable, so it can be swapped for a distributed worker later.
"""

import logging
import queue
import threading

from app.core.config import settings

log = logging.getLogger("siem.sca.queue")

_ACTIVE_STATUSES = ("queued", "running", "collecting", "evaluating")


class ScanJobQueue:
    def __init__(self, max_workers: int | None = None) -> None:
        self._jobs: queue.Queue[str] = queue.Queue()
        self._workers = max(1, max_workers or settings.sca_worker_threads)
        self._threads: list[threading.Thread] = []
        self._stopped = threading.Event()

    def enqueue(self, scan_id: str) -> None:
        self._jobs.put(scan_id)

    def start(self) -> None:
        if self._threads:
            return
        for index in range(self._workers):
            thread = threading.Thread(
                target=self._worker, name=f"sca-scan-{index}", daemon=True
            )
            thread.start()
            self._threads.append(thread)
        log.info("SCA scan worker started with %d thread(s)", self._workers)

    def stop(self) -> None:
        self._stopped.set()
        for _ in self._threads:
            self._jobs.put("")  # wake blocked workers

    # ------------------------------------------------------------- internal
    def _worker(self) -> None:
        from app.db.session import SessionLocal
        from app.models.sca import PolicyScan
        from app.sca.engine import ScanEngine

        while not self._stopped.is_set():
            scan_id = self._jobs.get()
            if not scan_id:
                continue
            if self._stopped.is_set():
                break
            try:
                with SessionLocal() as db:
                    scan = db.get(PolicyScan, scan_id)
                    if scan is not None and scan.status in _ACTIVE_STATUSES:
                        ScanEngine(db).run(scan)
            except Exception:
                log.exception("scan job %s failed", scan_id)


_scan_queue = ScanJobQueue()


def get_scan_queue() -> ScanJobQueue:
    return _scan_queue
