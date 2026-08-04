"""Collector worker entrypoint.

Runs the syslog receiver and file tailers as background tasks so the
endpoint-collection layer (function 1) keeps running alongside the pipeline.

Usage:
    python -m app.workers.collector_worker
"""

import asyncio
import logging

from app.core.logging import setup_logging
from app.ingestion import FileTailer, SyslogReceiver
from app.pipeline.bus import build_event_bus

setup_logging()
log = logging.getLogger("siem.worker.collector")


async def main() -> None:
    bus = build_event_bus()
    tasks = [
        asyncio.create_task(
            SyslogReceiver(bus).run(), name="syslog-receiver"
        ),
        asyncio.create_task(
            FileTailer(bus, source_name="endpoint-logs").run(),
            name="file-tailer",
        ),
    ]
    log.info("Collector worker started with %d tasks", len(tasks))
    await asyncio.gather(*tasks)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        log.info("Collector worker stopped")
