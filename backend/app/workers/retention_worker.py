"""Retention worker (function 9).

Periodically enforces the retention policy (ILM / local cleanup) and snapshots.
"""

import asyncio
import logging

from app.core.config import settings
from app.services.retention_service import RetentionService

log = logging.getLogger("siem.retention.worker")

INTERVAL_SECONDS = max(60, settings.retention_hot_days * 3600 // 3)


async def run_once() -> dict:
    report = await RetentionService().run()
    log.info("Retention run: %s", report)
    return report


async def main() -> None:
    log.info("Retention worker started (interval=%ss)", INTERVAL_SECONDS)
    while True:
        try:
            await run_once()
        except Exception:
            log.exception("Retention run failed")
        await asyncio.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    asyncio.run(main())
