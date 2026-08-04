"""Alerting worker (function 5).

Consumes the detections topic, consolidates detections into managed alerts in
the metadata DB (dedup + escalation), triggers webhook/email notifications and
re-publishes final alerts on the alerts topic for SOAR (M12) to consume.

Usage:
    python -m app.workers.alert_worker
"""

import asyncio
import logging
import uuid

from app.core.logging import setup_logging
from app.db.session import SessionLocal
from app.pipeline.bus import Topics, build_event_bus
from app.pipeline.detection import Detection
from app.services.alert_service import AlertService

setup_logging()
log = logging.getLogger("siem.worker.alerts")


async def run(group: str = "alerting") -> None:
    bus = build_event_bus()
    consumer = f"alert-worker-{uuid.uuid4().hex[:6]}"
    log.info("Alert worker consuming %s as %s", Topics.DETECTIONS, consumer)

    async for topic, payload, msg_id in bus.subscribe(
        [Topics.DETECTIONS], group, consumer
    ):
        try:
            detection = Detection(**payload)
            with SessionLocal() as db:
                service = AlertService(db, bus=bus)
                await service.process_detection(detection)
        except Exception:
            log.exception("Alert processing failed (msg=%s)", msg_id)
        await bus.ack(topic, group, msg_id)


def main() -> None:
    try:
        asyncio.run(run())
    except (KeyboardInterrupt, SystemExit):
        log.info("Alert worker stopped")


if __name__ == "__main__":
    main()
