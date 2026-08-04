"""Pipeline worker entrypoint.

Runs the ingest -> normalize -> detect stages:

    raw.events       -> (normalizer) -> normalized.events
    normalized.events -> (correlation + signatures + YARA + ML) -> detections

Consumers run in one process/event-loop; acking per message keeps at-least-once
delivery with the configured bus.

Usage:
    python -m app.workers.pipeline_worker
"""

import asyncio
import logging

from app.core.logging import setup_logging
from app.pipeline.bus import EventBus, Topics, build_event_bus
from app.services.detection_service import DetectionService
from app.services.normalizer_service import NormalizerService
from app.storage.base import build_log_store

setup_logging()
log = logging.getLogger("siem.worker.pipeline")


async def run(bus: EventBus, group: str = "pipeline") -> None:
    store = build_log_store()
    normalizer = NormalizerService(bus, store)
    detectors = DetectionService(bus)
    log.info("Pipeline worker started (normalizer + detection engines)")

    async def handle_raw() -> None:
        consumer = f"normalizer-{id(bus)}"
        async for topic, event, msg_id in bus.subscribe(
            [Topics.RAW_EVENTS], group, consumer
        ):
            try:
                await normalizer.process(event)
            except Exception:
                log.exception("Normalization failed (id=%s)", msg_id)
            await bus.ack(topic, group, msg_id)

    async def handle_normalized() -> None:
        consumer = f"detectors-{id(bus)}"
        async for topic, event, msg_id in bus.subscribe(
            [Topics.NORMALIZED_EVENTS], group, consumer
        ):
            try:
                await detectors.process_event(event)
            except Exception:
                log.exception("Detection failed (id=%s)", msg_id)
            await bus.ack(topic, group, msg_id)

    await asyncio.gather(handle_raw(), handle_normalized())


def main() -> None:
    bus = build_event_bus()
    try:
        asyncio.run(run(bus))
    except (KeyboardInterrupt, SystemExit):
        log.info("Pipeline worker stopped")


if __name__ == "__main__":
    main()
